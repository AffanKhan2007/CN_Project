#!/usr/bin/env python3
"""
Ryu (OpenFlow 1.3) controller for TCP-authentication-based network access control.

Run:  ACL_MODE=dynamic ryu-manager src/controller.py        (dynamic | static | open)

Flow-table layout (all in table 0, higher priority wins):
  300  BLOCK   drop everything from a brute-forcing IP            (hard_timeout = block time)
  200  ALLOW   per-client, per-service flows to/from h5           (hard_timeout = session TTL)
  150  DENY    short-lived drop for a denied (src,dst,proto,port) (idle_timeout = 10 s) -> logged once
  110  INFRA   auth server <-> controller event channel
  100  INFRA   anyone -> auth server :9000 (+ICMP), and the replies
   90  GUARD   drop all traffic to/from the controller IP
   50  generic east-west traffic, learned reactively (NORMAL)
   10  ARP -> NORMAL
    0  table-miss -> controller (packet_in)

Control channel: the auth server (h4) sends one JSON event per line over TCP to
<controller_ip>:9100 (GRANT / REVOKE / BLOCK); the controller answers "OK" once
the flow-mods are sent. Only the auth server's IP is accepted.

ACL_MODE (used for the evaluation baselines):
  dynamic  authentication drives the flow table (the proposed approach)
  static   fixed allow-list of IPs from config.json, auth events ignored (baseline 1)
  open     protected host reachable by everyone, no access control (baseline 2)
"""
import csv, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import icmp, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

import common
from common import AUTH_IP, AUTH_PORT, CFG, CTRL_IP, EVENT_PORT, PROTECTED_IP, get_logger

ETH_IP = 0x0800
ETH_ARP = 0x0806
PRIO_MISS, PRIO_ARP, PRIO_GENERIC = 0, 10, 50
PRIO_GUARD, PRIO_INFRA, PRIO_DENY, PRIO_ALLOW, PRIO_BLOCK = 90, 100, 150, 200, 300
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17}
L4_FIELDS = {"tcp": ("tcp_src", "tcp_dst"), "udp": ("udp_src", "udp_dst")}


def _mf(match, key):
    try:
        return match[key]
    except KeyError:
        return ""


class SdnAuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = os.environ.get("ACL_MODE", "dynamic").lower()
        self.roles = CFG["roles"]
        self.static_allowed = set(CFG["static_allowed_ips"])
        self.dps = {}
        self.sessions = {}      # client ip -> {user, role, expires}
        self.blocked = {}       # client ip -> until
        self.log = get_logger("controller", "controller.log")
        self.log.info("controller starting, ACL_MODE=%s", self.mode)
        hub.spawn(self._event_server)
        hub.spawn(self._stats_loop)

    # ------------------------------------------------------------------ helpers
    def add_flow(self, dp, prio, match, actions, idle=0, hard=0, rem=False):
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        flags = ofp.OFPFF_SEND_FLOW_REM if rem else 0
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst,
                                 idle_timeout=idle, hard_timeout=min(hard, 65535), flags=flags))

    def del_flows(self, dp, match):
        ofp, p = dp.ofproto, dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                 out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match))

    def normal(self, dp):
        return [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)]

    def svc_matches(self, client, svc):
        """OpenFlow match dicts (forward, reverse) for one service between client and the protected host."""
        fwd = dict(eth_type=ETH_IP, ipv4_src=client, ipv4_dst=PROTECTED_IP)
        rev = dict(eth_type=ETH_IP, ipv4_src=PROTECTED_IP, ipv4_dst=client)
        if svc == "*":
            return [fwd, rev]
        if svc == "icmp":
            fwd["ip_proto"] = rev["ip_proto"] = 1
            return [fwd, rev]
        proto, port = svc.split(":")
        src_f, dst_f = L4_FIELDS[proto]
        fwd.update(ip_proto=PROTO_NUM[proto], **{dst_f: int(port)})
        rev.update(ip_proto=PROTO_NUM[proto], **{src_f: int(port)})
        return [fwd, rev]

    # ------------------------------------------------------------------ switch lifecycle
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self.dps[dp.id] = dp
        self.del_flows(dp, p.OFPMatch())                      # start from a clean table
        self.add_flow(dp, PRIO_MISS, p.OFPMatch(),
                      [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self._baseline(dp)
        self.log.info("switch s%s connected, baseline flows installed (mode=%s)", dp.id, self.mode)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state(self, ev):
        if ev.state == DEAD_DISPATCHER and ev.datapath:
            self.dps.pop(ev.datapath.id, None)

    def _baseline(self, dp):
        p = dp.ofproto_parser
        M, N = p.OFPMatch, self.normal(dp)
        self.add_flow(dp, PRIO_ARP, M(eth_type=ETH_ARP), N)
        # the controller must not be reachable from hosts (only from the auth server)
        self.add_flow(dp, PRIO_GUARD, M(eth_type=ETH_IP, ipv4_dst=CTRL_IP), [])
        self.add_flow(dp, PRIO_GUARD, M(eth_type=ETH_IP, ipv4_src=CTRL_IP), [])
        self.add_flow(dp, PRIO_INFRA + 10, M(eth_type=ETH_IP, ipv4_src=AUTH_IP, ipv4_dst=CTRL_IP), N)
        self.add_flow(dp, PRIO_INFRA + 10, M(eth_type=ETH_IP, ipv4_src=CTRL_IP, ipv4_dst=AUTH_IP), N)
        # the authentication service is reachable by every host (login must be possible)
        self.add_flow(dp, PRIO_INFRA, M(eth_type=ETH_IP, ip_proto=6, ipv4_dst=AUTH_IP, tcp_dst=AUTH_PORT), N)
        self.add_flow(dp, PRIO_INFRA, M(eth_type=ETH_IP, ip_proto=6, ipv4_src=AUTH_IP, tcp_src=AUTH_PORT), N)
        self.add_flow(dp, PRIO_INFRA, M(eth_type=ETH_IP, ip_proto=1, ipv4_dst=AUTH_IP), N)
        self.add_flow(dp, PRIO_INFRA, M(eth_type=ETH_IP, ip_proto=1, ipv4_src=AUTH_IP), N)
        if self.mode == "open":
            self.add_flow(dp, PRIO_ALLOW, M(eth_type=ETH_IP, ipv4_dst=PROTECTED_IP), N)
            self.add_flow(dp, PRIO_ALLOW, M(eth_type=ETH_IP, ipv4_src=PROTECTED_IP), N)
        elif self.mode == "static":
            for ip in self.static_allowed:
                for m in self.svc_matches(ip, "*"):
                    self.add_flow(dp, PRIO_ALLOW, M(**m), N)

    # ------------------------------------------------------------------ auth-server event channel
    def _event_server(self):
        bind = os.environ.get("EVENT_BIND", "0.0.0.0")
        srv = hub.StreamServer((bind, EVENT_PORT), self._on_event_conn)
        self.log.info("event channel listening on %s:%d (trusted peer %s)", bind, EVENT_PORT,
                      os.environ.get("TRUSTED_AUTH_IP", AUTH_IP))
        srv.serve_forever()

    def _on_event_conn(self, sock, addr):
        trusted = os.environ.get("TRUSTED_AUTH_IP", AUTH_IP)
        if addr[0] != trusted:
            self.log.warning("REJECT event connection from untrusted %s", addr[0])
            sock.close()
            return
        f = sock.makefile("r")
        self.log.info("auth server connected from %s", addr[0])
        try:
            while True:
                line = f.readline()
                if not line:
                    break
                try:
                    self._handle_event(json.loads(line))
                    sock.sendall(b"OK\n")
                except Exception as e:
                    self.log.error("bad event %r: %s", line.strip(), e)
                    sock.sendall(b"ERR\n")
        finally:
            sock.close()

    def _handle_event(self, ev):
        kind = ev["event"]
        if kind == "GRANT":
            self._grant(ev["ip"], ev["user"], ev["role"], int(ev["ttl"]))
        elif kind == "REVOKE":
            self._revoke(ev["ip"], ev.get("reason", "unspecified"))
        elif kind == "BLOCK":
            self._block(ev["ip"], int(ev["duration"]))
        else:
            raise ValueError("unknown event " + kind)

    # ------------------------------------------------------------------ dynamic rule management
    def _grant(self, ip, user, role, ttl):
        if self.mode != "dynamic":
            self.log.info("GRANT ip=%s user=%s ignored (mode=%s)", ip, user, self.mode)
            return
        if role not in self.roles:
            raise ValueError("unknown role " + role)
        if self.blocked.get(ip, 0) > time.time():
            raise ValueError("ip %s is blocked" % ip)
        self._delete_pair(ip)                                  # drop stale flows of an older role
        self.sessions[ip] = {"user": user, "role": role, "expires": time.time() + ttl}
        n = 0
        for dp in self.dps.values():
            for svc in self.roles[role]:
                for m in self.svc_matches(ip, svc):
                    self.add_flow(dp, PRIO_ALLOW, dp.ofproto_parser.OFPMatch(**m), self.normal(dp),
                                  hard=ttl, rem=True)
                    n += 1
        self.log.info("GRANT ip=%s user=%s role=%s ttl=%ds services=%s -> %d flow-mods",
                      ip, user, role, ttl, self.roles[role], n)

    def _delete_pair(self, ip):
        for dp in self.dps.values():
            M = dp.ofproto_parser.OFPMatch
            self.del_flows(dp, M(eth_type=ETH_IP, ipv4_src=ip, ipv4_dst=PROTECTED_IP))
            self.del_flows(dp, M(eth_type=ETH_IP, ipv4_src=PROTECTED_IP, ipv4_dst=ip))

    def _revoke(self, ip, reason):
        if self.mode != "dynamic":
            self.log.info("REVOKE ip=%s ignored (mode=%s)", ip, self.mode)
            return
        s = self.sessions.pop(ip, None)
        self._delete_pair(ip)
        self.log.info("REVOKE ip=%s user=%s reason=%s -> flows removed", ip, s and s["user"], reason)

    def _block(self, ip, duration):
        if self.mode != "dynamic":
            self.log.info("BLOCK ip=%s ignored (mode=%s)", ip, self.mode)
            return
        self.sessions.pop(ip, None)
        self._delete_pair(ip)
        self.blocked[ip] = time.time() + duration
        for dp in self.dps.values():
            self.add_flow(dp, PRIO_BLOCK, dp.ofproto_parser.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), [],
                          hard=duration, rem=True)
        self.log.warning("BLOCK ip=%s for %ds (all traffic dropped at the switches)", ip, duration)

    # ------------------------------------------------------------------ reactive decisions
    @staticmethod
    def _l4(pkt, ip4):
        t = pkt.get_protocol(tcp.tcp)
        if t:
            return "tcp", t.src_port, t.dst_port
        u = pkt.get_protocol(udp.udp)
        if u:
            return "udp", u.src_port, u.dst_port
        if pkt.get_protocol(icmp.icmp):
            return "icmp", 0, 0
        return "ip%d" % ip4.proto, 0, 0

    def _permitted(self, client, proto, port):
        if self.mode == "open":
            return True, "open"
        if self.mode == "static":
            ok = client in self.static_allowed
            return ok, "static-acl" if ok else "not-in-static-acl"
        if self.blocked.get(client, 0) > time.time():
            return False, "blocked"
        s = self.sessions.get(client)
        if not s or s["expires"] <= time.time():
            return False, "not-authenticated"
        for a in self.roles.get(s["role"], []):
            if a == "*" or a == proto or a == "%s:%s" % (proto, port):
                return True, "role=%s user=%s" % (s["role"], s["user"])
        return False, "role=%s not permitted %s:%s" % (s["role"], proto, port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return
        src, dst = ip4.src, ip4.dst
        proto, sport, dport = self._l4(pkt, ip4)

        if AUTH_IP in (src, dst):                              # only :9000 and ICMP are allowed (baseline flows)
            self._deny(dp, src, dst, proto, sport, dport, "auth-server-accepts-only-tcp/%d" % AUTH_PORT)
            return
        if dst == PROTECTED_IP:
            client, port = src, dport
        elif src == PROTECTED_IP:
            client, port = dst, sport
        else:
            self._allow_generic(dp, msg, src, dst)
            return
        ok, reason = self._permitted(client, proto, port)
        if ok:
            self._allow_protected(dp, msg, client, proto, port, reason)
        else:
            self._deny(dp, src, dst, proto, sport, dport, reason)

    def _allow_generic(self, dp, msg, src, dst):
        p = dp.ofproto_parser
        self.add_flow(dp, PRIO_GENERIC, p.OFPMatch(eth_type=ETH_IP, ipv4_src=src, ipv4_dst=dst),
                      self.normal(dp), idle=30)
        self._packet_out(dp, msg)

    def _allow_protected(self, dp, msg, client, proto, port, reason):
        p = dp.ofproto_parser
        svc = proto if proto == "icmp" else "%s:%s" % (proto, port)
        if proto not in PROTO_NUM:
            svc = "*"
        hard = 0
        s = self.sessions.get(client)
        if self.mode == "dynamic" and s:
            hard = max(1, int(s["expires"] - time.time()))
        for m in self.svc_matches(client, svc):
            self.add_flow(dp, PRIO_ALLOW, p.OFPMatch(**m), self.normal(dp),
                          idle=0 if hard else 30, hard=hard, rem=True)
        self._packet_out(dp, msg)
        self.log.info("ALLOW %s -> %s %s (%s)", client, PROTECTED_IP, svc, reason)

    def _deny(self, dp, src, dst, proto, sport, dport, reason):
        p = dp.ofproto_parser
        fields = dict(eth_type=ETH_IP, ipv4_src=src, ipv4_dst=dst)
        if proto in PROTO_NUM:
            fields["ip_proto"] = PROTO_NUM[proto]
            if proto in L4_FIELDS:
                fields[L4_FIELDS[proto][1]] = dport
        self.add_flow(dp, PRIO_DENY, p.OFPMatch(**fields), [], idle=10, rem=True)
        self.log.warning("DENY %s -> %s %s:%s (%s)", src, dst, proto, dport, reason)

    def _packet_out(self, dp, msg):
        ofp, p = dp.ofproto, dp.ofproto_parser
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=msg.match["in_port"],
                                   actions=self.normal(dp), data=msg.data))

    # ------------------------------------------------------------------ accounting / logging
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        m = ev.msg
        src, dst = _mf(m.match, "ipv4_src"), _mf(m.match, "ipv4_dst")
        why = {0: "idle-timeout", 1: "hard-timeout", 2: "deleted"}.get(m.reason, str(m.reason))
        if m.priority == PRIO_DENY:
            self.log.info("DENY_SUMMARY %s -> %s dropped_packets=%d bytes=%d (flow %s)",
                          src, dst, m.packet_count, m.byte_count, why)
        elif m.priority == PRIO_ALLOW and m.reason != 2:
            self.log.info("SESSION_FLOW_EXPIRED %s <-> %s packets=%d bytes=%d (%s)",
                          src, dst, m.packet_count, m.byte_count, why)
        elif m.priority == PRIO_BLOCK:
            self.blocked.pop(src, None)
            self.log.info("UNBLOCK ip=%s (%s)", src, why)

    def _stats_loop(self):
        interval = float(os.environ.get("STATS_INTERVAL", 5))
        path = os.path.join(common.LOG_DIR, "flow_stats.csv")
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(["time", "dpid", "src", "dst", "ip_proto", "port", "packets", "bytes"])
        while True:
            hub.sleep(interval)
            for dp in list(self.dps.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        rows = []
        for st in ev.msg.body:
            if st.priority != PRIO_ALLOW:
                continue
            m = st.match
            rows.append([round(time.time(), 1), ev.msg.datapath.id, _mf(m, "ipv4_src"), _mf(m, "ipv4_dst"),
                         _mf(m, "ip_proto"), _mf(m, "tcp_dst") or _mf(m, "tcp_src"),
                         st.packet_count, st.byte_count])
        if rows:
            with open(os.path.join(common.LOG_DIR, "flow_stats.csv"), "a", newline="") as f:
                csv.writer(f).writerows(rows)

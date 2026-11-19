#!/usr/bin/env python3
"""
TCP authentication server (runs on h4).

Protocol (line based, UTF-8, '\n' terminated):
  S: HELLO sdn-auth/1.0
  C: LOGIN <user>            S: CHALLENGE <nonce>
  C: RESPONSE <hmac>         S: OK <token> <role> <ttl>   |  FAIL <reason>
  C: STATUS                  S: OK <user> <role> <remaining_s>  | FAIL no_session
  C: RENEW                   S: OK <ttl>                        | FAIL no_session
  C: LOGOUT                  S: OK bye
  C: QUIT                    (connection closed)
A session is bound to the client's source IP. Every state change is pushed to
the SDN controller over a TCP event channel (GRANT / REVOKE / BLOCK); the
controller turns it into OpenFlow rules. Login is fail-closed: if the
controller does not acknowledge GRANT, the login fails.
"""
import argparse, hmac, json, secrets, socket, threading, time
from collections import deque

from common import (AUTH_PORT, CFG, CTRL_IP, EVENT_PORT, challenge_response,
                    get_logger, load_json, new_nonce)

log = get_logger("auth", "auth.log")
alog = get_logger("access", "access.log", console=False)


class Notifier:
    """Persistent TCP channel to the controller; every event must be ACKed."""

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = self.rfile = None
        self.lock = threading.Lock()

    def _connect(self):
        s = socket.create_connection((self.host, self.port), timeout=2)
        s.settimeout(3)
        self.sock, self.rfile = s, s.makefile("r")

    def _close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = self.rfile = None

    def send(self, event):
        data = (json.dumps(event) + "\n").encode()
        with self.lock:
            for _ in range(2):
                try:
                    if self.sock is None:
                        self._connect()
                    t0 = time.time()
                    self.sock.sendall(data)
                    resp = self.rfile.readline().strip()
                    if resp == "OK":
                        log.info("controller ACK %s ip=%s rtt_ms=%.1f", event["event"],
                                 event.get("ip"), (time.time() - t0) * 1000)
                        return True
                    raise IOError("bad ack %r" % resp)
                except Exception as e:
                    log.warning("notify failed (%s): %s", event["event"], e)
                    self._close()
        return False


class AuthServer:
    def __init__(self, args):
        self.args = args
        self.users = load_json("users.json")
        self.sessions = {}      # ip -> dict(user, role, token, expires, since)
        self.fails = {}         # ip -> [timestamps]
        self.blocked = {}       # ip -> until
        self.lock = threading.RLock()
        self.pending = deque(maxlen=200)
        self.notifier = Notifier(args.ctrl_host, args.ctrl_port)

    # ---------- controller notification ----------
    def notify(self, event, critical=False):
        ok = self.notifier.send(event)
        if not ok and not critical:
            self.pending.append(event)
        return ok

    # ---------- policy helpers ----------
    def register_failure(self, ip, user):
        now = time.time()
        blocked_now = False
        with self.lock:
            lst = [t for t in self.fails.get(ip, []) if now - t < self.args.fail_window]
            lst.append(now)
            self.fails[ip] = lst
            n = len(lst)
            if n >= self.args.max_fails:
                self.blocked[ip] = now + self.args.block_secs
                self.fails[ip] = []
                self.sessions.pop(ip, None)
                blocked_now = True
        alog.info("LOGIN_FAIL ip=%s user=%s attempts=%d", ip, user, n)
        if blocked_now:
            alog.info("BLOCK ip=%s duration=%ds reason=too_many_failures", ip, self.args.block_secs)
            self.notify({"event": "BLOCK", "ip": ip, "duration": self.args.block_secs})
        return blocked_now

    # ---------- command handlers ----------
    def do_login(self, ip, user, conn, rfile):
        send = lambda m: conn.sendall((m + "\n").encode())
        now = time.time()
        with self.lock:
            until = self.blocked.get(ip, 0)
        if until > now:
            alog.info("LOGIN_REFUSED ip=%s user=%s reason=blocked remaining=%ds", ip, user, until - now)
            send("FAIL blocked %d" % (until - now))
            return
        nonce = new_nonce()
        send("CHALLENGE " + nonce)
        parts = (rfile.readline(512) or "").strip().split()
        if len(parts) != 2 or parts[0].upper() != "RESPONSE":
            send("FAIL protocol_error")
            return
        rec = self.users.get(user)            # unknown users still get a challenge (no enumeration)
        ok = bool(rec) and hmac.compare_digest(challenge_response(rec["hash"], nonce), parts[1])
        if not ok:
            blocked = self.register_failure(ip, user)
            send(("FAIL blocked %d" % self.args.block_secs) if blocked else "FAIL bad_credentials")
            return
        role, ttl = rec["role"], self.args.ttl
        ev = {"event": "GRANT", "ip": ip, "user": user, "role": role, "ttl": ttl}
        if not self.notify(ev, critical=True):
            alog.info("LOGIN_ERROR ip=%s user=%s reason=controller_unavailable", ip, user)
            send("FAIL controller_unavailable")
            return
        token = secrets.token_hex(8)
        with self.lock:
            self.fails.pop(ip, None)
            self.sessions[ip] = {"user": user, "role": role, "token": token,
                                 "expires": time.time() + ttl, "since": time.time()}
        alog.info("GRANT ip=%s user=%s role=%s ttl=%ds", ip, user, role, ttl)
        send("OK %s %s %d" % (token, role, ttl))

    def do_status(self, ip):
        with self.lock:
            s = self.sessions.get(ip)
            if not s:
                return "FAIL no_session"
            return "OK %s %s %d" % (s["user"], s["role"], max(0, s["expires"] - time.time()))

    def do_renew(self, ip):
        with self.lock:
            s = self.sessions.get(ip)
        if not s:
            return "FAIL no_session"
        ev = {"event": "GRANT", "ip": ip, "user": s["user"], "role": s["role"], "ttl": self.args.ttl}
        if not self.notify(ev, critical=True):
            return "FAIL controller_unavailable"
        with self.lock:
            s["expires"] = time.time() + self.args.ttl
        alog.info("RENEW ip=%s user=%s ttl=%ds", ip, s["user"], self.args.ttl)
        return "OK %d" % self.args.ttl

    def do_logout(self, ip):
        with self.lock:
            s = self.sessions.pop(ip, None)
        if not s:
            return "FAIL no_session"
        self.notify({"event": "REVOKE", "ip": ip, "reason": "logout"})
        alog.info("REVOKE ip=%s user=%s reason=logout", ip, s["user"])
        return "OK bye"

    # ---------- per-connection thread ----------
    def serve(self, conn, addr):
        ip = addr[0]
        conn.settimeout(self.args.conn_timeout)
        rfile = conn.makefile("r", encoding="utf-8", newline="\n")
        send = lambda m: conn.sendall((m + "\n").encode())
        log.info("connection from %s:%d", *addr)
        try:
            send("HELLO sdn-auth/1.0")
            while True:
                line = rfile.readline(512)
                if not line:
                    break
                parts = line.strip().split()
                if not parts:
                    continue
                cmd = parts[0].upper()
                if cmd == "LOGIN" and len(parts) == 2:
                    self.do_login(ip, parts[1], conn, rfile)
                elif cmd == "STATUS":
                    send(self.do_status(ip))
                elif cmd == "RENEW":
                    send(self.do_renew(ip))
                elif cmd == "LOGOUT":
                    send(self.do_logout(ip))
                elif cmd == "QUIT":
                    break
                else:
                    send("ERR unknown_command")
        except (socket.timeout, ConnectionError, OSError, UnicodeDecodeError) as e:
            log.info("connection %s closed: %s", ip, e)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ---------- background reaper ----------
    def reaper(self):
        while True:
            time.sleep(0.5)
            now = time.time()
            expired = []
            with self.lock:
                for ip, s in list(self.sessions.items()):
                    if s["expires"] <= now:
                        expired.append((ip, s["user"]))
                        del self.sessions[ip]
                for ip, until in list(self.blocked.items()):
                    if until <= now:
                        del self.blocked[ip]
                        alog.info("UNBLOCK ip=%s", ip)
            for ip, user in expired:
                alog.info("REVOKE ip=%s user=%s reason=timeout", ip, user)
                self.notify({"event": "REVOKE", "ip": ip, "reason": "timeout"})
            for _ in range(len(self.pending)):      # retry events that failed earlier
                ev = self.pending.popleft()
                if not self.notifier.send(ev):
                    self.pending.append(ev)
                    break

    def run(self):
        threading.Thread(target=self.reaper, daemon=True).start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.args.host, self.args.port))
        srv.listen(128)
        log.info("auth server listening on %s:%d (ttl=%ds, max_fails=%d, block=%ds)",
                 self.args.host, self.args.port, self.args.ttl, self.args.max_fails, self.args.block_secs)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.serve, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=AUTH_PORT)
    ap.add_argument("--ctrl-host", default=CTRL_IP)
    ap.add_argument("--ctrl-port", type=int, default=EVENT_PORT)
    ap.add_argument("--ttl", type=int, default=CFG["session_ttl"])
    ap.add_argument("--max-fails", type=int, default=CFG["max_failed_attempts"])
    ap.add_argument("--fail-window", type=int, default=CFG["fail_window_secs"])
    ap.add_argument("--block-secs", type=int, default=CFG["block_secs"])
    ap.add_argument("--conn-timeout", type=int, default=60)
    AuthServer(ap.parse_args()).run()

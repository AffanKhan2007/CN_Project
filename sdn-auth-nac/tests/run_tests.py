#!/usr/bin/env python3
"""
Functional test-suite (needs the controller running in ACL_MODE=dynamic):
    ryu-manager src/controller.py &
    sudo python3 tests/run_tests.py
Starts its own Mininet network, runs all scenarios and prints a PASS/FAIL table.
"""
import json, os, sys, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "topology"))
import topo  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

SRC, P, AUTH = topo.SRC, topo.PROTECTED_IP, topo.AUTH_IP
TTL, BLOCK = 10, 15
results = []


def sh(host, cmd):
    out = host.cmd(cmd + " 2>&1; echo __RC=$?")
    return int(out.rsplit("__RC=", 1)[1].strip()), out


def access(host, port, mode=None):
    extra = " --mode " + mode if mode else ""
    return sh(host, "python3 %s/svc_probe.py %s %d --timeout 2%s" % (SRC, P, port, extra))[0] == 0


def ping(host):
    return sh(host, "ping -c 2 -W 1 %s" % P)[0] == 0


def auth(host, user, pw, actions="login"):
    return sh(host, "python3 %s/auth_client.py --host %s --user %s --password %s --actions %s"
              % (SRC, AUTH, user, pw, actions))


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print("  [%s] %s %s" % ("PASS" if cond else "FAIL", name, detail))


def main():
    setLogLevel("warning")
    net = topo.build_network()
    net.start()
    topo.wait_for_switches(net)
    topo.start_services(net, ttl=TTL, block_secs=BLOCK, max_fails=3)
    h1, h2, h3, h6 = net["h1"], net["h2"], net["h3"], net["h6"]
    try:
        print("\nT1 unauthenticated host is denied")
        check("T1.1 h6 -> web denied", not access(h6, 8080))
        check("T1.2 h6 -> data denied", not access(h6, 9090))
        check("T1.3 h6 ping protected denied", not ping(h6))
        check("T1.4 h6 can still reach auth server", sh(h6, "python3 %s/svc_probe.py %s 9000 --mode connect" % (SRC, AUTH))[0] == 0)
        check("T1.5 h6 cannot reach controller (10.0.0.254:9100)",
              sh(h6, "python3 %s/svc_probe.py 10.0.0.254 9100 --mode connect --timeout 2" % SRC)[0] != 0)

        print("\nT2 admin (alice, h1) gets full access")
        rc, out = auth(h1, "alice", "alice123", "login,status")
        check("T2.1 login ok", rc == 0, out.split("\n")[0].strip())
        time.sleep(0.5)
        check("T2.2 web allowed", access(h1, 8080))
        check("T2.3 data allowed", access(h1, 9090))
        check("T2.4 ping allowed", ping(h1))

        print("\nT3 role policies (least privilege)")
        check("T3.1 bob(user) login", auth(h2, "bob", "bob123")[0] == 0)
        time.sleep(0.5)
        check("T3.2 bob web allowed", access(h2, 8080))
        check("T3.3 bob ping allowed", ping(h2))
        check("T3.4 bob data DENIED", not access(h2, 9090))
        check("T3.5 guest login", auth(h3, "guest", "guest123")[0] == 0)
        time.sleep(0.5)
        check("T3.6 guest web allowed", access(h3, 8080))
        check("T3.7 guest data DENIED", not access(h3, 9090))
        check("T3.8 guest ping DENIED", not ping(h3))

        print("\nT4 logout revokes access dynamically")
        auth(h2, "bob", "bob123")   # fresh session (bob's T3 session expires, ttl=10s)
        check("T4.1 alice logout ok", auth(h1, "alice", "alice123", "login,logout")[0] == 0)
        time.sleep(0.5)
        check("T4.2 h1 web denied after logout", not access(h1, 8080))
        check("T4.3 h1 ping denied after logout", not ping(h1))
        check("T4.4 other sessions unaffected (bob web)", access(h2, 8080))

        print("\nT5 session timeout (ttl=%ds)" % TTL)
        check("T5.1 alice login", auth(h1, "alice", "alice123")[0] == 0)
        time.sleep(0.5)
        check("T5.2 access before expiry", access(h1, 8080))
        time.sleep(TTL + 2.5)
        check("T5.3 access denied after expiry", not access(h1, 8080))
        rc, out = auth(h1, "alice", "alice123", "status")
        check("T5.4 status says no_session", "no_session" in out, "")

        print("\nT6 wrong credentials / brute-force protection")
        rc, out = auth(h6, "alice", "wrongpw")
        check("T6.1 wrong password rejected", rc != 0 and "bad_credentials" in out)
        rc, out = auth(h6, "mallory", "x")
        check("T6.2 unknown user rejected", rc != 0)
        auth(h6, "alice", "bad3")                              # 3rd failure -> blocked
        rc, out = auth(h6, "alice", "alice123")                # correct pw but blocked
        check("T6.3 blocked even with correct password", rc != 0)
        check("T6.4 blocked host cannot ping auth server", sh(h6, "ping -c 1 -W 1 %s" % AUTH)[0] != 0)
        time.sleep(BLOCK + 2)
        rc, out = auth(h6, "alice", "alice123", "login,logout")
        check("T6.5 block expires automatically, login works again", rc == 0, out.split("\n")[0].strip())

        print("\nT7 concurrency")
        rc, out = sh(h2, "python3 %s/auth_stress.py --clients 20 --rounds 3 --users alice:alice123,bob:bob123,carol:carol123" % SRC)
        summary = json.loads(out.strip().split("\n")[-2]) if rc == 0 else {}
        check("T7.1 60 concurrent logins all succeed", rc == 0, json.dumps(summary))
        auth(h2, "bob", "bob123", "login,logout")

        print("\nT8 logs")
        def lines(f, pat):
            return int(sh(h1, "grep -c '%s' %s/logs/%s" % (pat, BASE, f))[1].split("\n")[0].strip() or 0)
        check("T8.1 access.log has GRANT", lines("access.log", "GRANT") > 0)
        check("T8.2 access.log has REVOKE logout+timeout", lines("access.log", "REVOKE") > 1)
        check("T8.3 access.log has BLOCK", lines("access.log", "BLOCK") > 0)
        check("T8.4 controller.log has DENY decisions", lines("controller.log", "DENY") > 0)
        check("T8.5 controller.log has ALLOW/flow-mod entries", lines("controller.log", "flow-mods") > 0)
    finally:
        topo.stop_services(net)
        net.stop()
    failed = [r for r in results if not r[1]]
    print("\n==== %d/%d checks passed ====" % (len(results) - len(failed), len(results)))
    for n, _, d in failed:
        print("FAILED:", n, d)
    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    with open(os.path.join(BASE, "results", "functional_tests.json"), "w") as f:
        json.dump([{"test": n, "pass": ok, "detail": d} for n, ok, d in results], f, indent=2)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

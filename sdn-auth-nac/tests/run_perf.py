#!/usr/bin/env python3
"""
Performance experiment for ONE controller mode (the controller must already be running with the same ACL_MODE):
    ACL_MODE=dynamic ryu-manager src/controller.py &
    sudo python3 tests/run_perf.py --mode dynamic
Use scripts/run_all_experiments.sh to run dynamic / static / open back to back.
"""
import argparse, json, os, re, statistics, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "topology"))
import topo  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

SRC, P, AUTH = topo.SRC, topo.PROTECTED_IP, topo.AUTH_IP


def sh(host, cmd):
    out = host.cmd(cmd + " 2>&1; echo __RC=$?")
    return int(out.rsplit("__RC=", 1)[1].strip()), out.rsplit("__RC=", 1)[0].strip()


def last_json(out):
    for line in reversed(out.split("\n")):
        if line.startswith("{"):
            return json.loads(line)
    return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["dynamic", "static", "open"])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--mb", type=int, default=50)
    a = ap.parse_args()
    setLogLevel("warning")
    net = topo.build_network()
    net.start()
    topo.wait_for_switches(net)
    topo.start_services(net, ttl=600)
    h1, h3, h6 = net["h1"], net["h3"], net["h6"]
    res = {"mode": a.mode}
    try:
        # 1. authentication service performance (sequential and concurrent)
        _, o = sh(h1, "python3 %s/auth_stress.py --clients 1 --rounds 30" % SRC)
        res["login_sequential"] = last_json(o)
        _, o = sh(h1, "python3 %s/auth_stress.py --clients 20 --rounds 3" % SRC)
        res["login_concurrent_20"] = last_json(o)

        # 2. grant / revocation latency
        lat = []
        for _ in range(a.runs):
            _, o = sh(h1, "python3 %s/latency_probe.py" % SRC)
            lat.append(last_json(o))
        res["grant_latency_ms"] = [x.get("login_to_access_ms") for x in lat]
        res["revocation_ms"] = [x.get("revocation_ms") if x.get("revoked") else None for x in lat]

        # 3. data-plane overhead after authentication
        sh(h1, "python3 %s/auth_client.py --user alice --password alice123" % SRC)
        mbps = []
        for _ in range(a.runs):
            _, o = sh(h1, "python3 %s/svc_probe.py %s 9090 --bytes %d --timeout 5" % (SRC, P, a.mb * 1024 * 1024))
            m = re.search(r"mbps=([\d.]+)", o)
            mbps.append(float(m.group(1)) if m else 0.0)
        res["throughput_mbps"] = mbps
        _, o = sh(h1, "ping -c 20 -i 0.2 %s" % P)
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", o)
        res["ping_avg_ms"] = float(m.group(2)) if m else None
        res["ping_loss"] = "100% packet loss" in o

        # 4. security outcome matrix
        res["unauth_h6_web_allowed"] = sh(h6, "python3 %s/svc_probe.py %s 8080 --timeout 2" % (SRC, P))[0] == 0
        sh(h3, "python3 %s/auth_client.py --user guest --password guest123" % SRC)
        res["authed_h3_web_allowed"] = sh(h3, "python3 %s/svc_probe.py %s 8080 --timeout 2" % (SRC, P))[0] == 0
        res["authed_h3_data_allowed"] = sh(h3, "python3 %s/svc_probe.py %s 9090 --timeout 2" % (SRC, P))[0] == 0
    finally:
        topo.stop_services(net)
        net.stop()
    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    out = os.path.join(BASE, "results", "perf_%s.json" % a.mode)
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))
    print("saved", out)


if __name__ == "__main__":
    main()

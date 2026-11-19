#!/usr/bin/env python3
"""Merge results/perf_{dynamic,static,open}.json into a markdown table (+ PNG charts if matplotlib is installed)."""
import json, os, statistics

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(BASE, "results")
modes = [m for m in ("open", "static", "dynamic") if os.path.exists(os.path.join(R, "perf_%s.json" % m))]
data = {m: json.load(open(os.path.join(R, "perf_%s.json" % m))) for m in modes}


def avg(v):
    v = [x for x in (v or []) if x is not None]
    return round(statistics.mean(v), 1) if v else None


def revoc(d):
    v = d.get("revocation_ms") or []
    done = [x for x in v if x is not None]
    return "never (>5000)" if not done else str(round(statistics.mean(done), 1))


rows = [
    ("Login latency, sequential (mean ms)", lambda d: d["login_sequential"].get("mean_ms")),
    ("Login latency, 20 concurrent (p95 ms)", lambda d: d["login_concurrent_20"].get("p95_ms")),
    ("Login -> first access (mean ms)", lambda d: avg(d.get("grant_latency_ms"))),
    ("Logout -> access blocked (mean ms)", revoc),
    ("TCP throughput after auth (Mbps)", lambda d: avg(d.get("throughput_mbps"))),
    ("Ping RTT after auth (ms)", lambda d: d.get("ping_avg_ms")),
    ("Unauthenticated host reaches service?", lambda d: "YES (leak)" if d.get("unauth_h6_web_allowed") else "no"),
    ("Authenticated guest (not in static list) gets web?", lambda d: "yes" if d.get("authed_h3_web_allowed") else "NO"),
    ("Guest reaches data port 9090 (least privilege)?", lambda d: "YES (over-permissive)" if d.get("authed_h3_data_allowed") else "no"),
]
lines = ["| Metric | " + " | ".join(modes) + " |", "|---|" + "---|" * len(modes)]
for name, fn in rows:
    lines.append("| %s | %s |" % (name, " | ".join(str(fn(data[m])) for m in modes)))
table = "\n".join(lines)
print(table)
open(os.path.join(R, "comparison.md"), "w").write(table + "\n")
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 3, figsize=(13, 3.6))
    for a_, (title, fn) in zip(ax, [("Throughput (Mbps)", lambda d: avg(d.get("throughput_mbps"))),
                                    ("Ping RTT (ms)", lambda d: d.get("ping_avg_ms")),
                                    ("Login -> access (ms)", lambda d: avg(d.get("grant_latency_ms")))]):
        a_.bar(modes, [fn(data[m]) or 0 for m in modes], color=["#999", "#6a9", "#47c"][:len(modes)])
        a_.set_title(title)
    plt.tight_layout()
    plt.savefig(os.path.join(R, "comparison.png"), dpi=140)
    print("chart saved to results/comparison.png")
except ImportError:
    print("(matplotlib not installed - skipping chart)")

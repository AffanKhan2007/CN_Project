#!/usr/bin/env python3
"""Concurrent login load generator -> prints a JSON summary."""
import argparse, json, statistics, threading, time

from common import AUTH_IP, AUTH_PORT
from auth_client import AuthClient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=AUTH_IP)
    ap.add_argument("--port", type=int, default=AUTH_PORT)
    ap.add_argument("--clients", type=int, default=10, help="concurrent client threads")
    ap.add_argument("--rounds", type=int, default=3, help="logins per thread")
    ap.add_argument("--users", default="alice:alice123", help="user:pw,user:pw (round-robin)")
    a = ap.parse_args()
    creds = [u.split(":") for u in a.users.split(",")]
    lat, counts, lock = [], {"ok": 0, "bad": 0}, threading.Lock()

    def worker(i):
        user, pw = creds[i % len(creds)]
        for _ in range(a.rounds):
            t0 = time.time()
            try:
                c = AuthClient(a.host, a.port, timeout=10)
                r = c.login(user, pw)
                c.close()
                good = r.startswith("OK")
            except Exception:
                good = False
            dt = (time.time() - t0) * 1000
            with lock:
                if good:
                    lat.append(dt)
                    counts["ok"] += 1
                else:
                    counts["bad"] += 1

    t0 = time.time()
    ths = [threading.Thread(target=worker, args=(i,)) for i in range(a.clients)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    lat.sort()
    out = {"clients": a.clients, "rounds": a.rounds, "ok": counts["ok"], "failed": counts["bad"],
           "wall_s": round(time.time() - t0, 2),
           "mean_ms": round(statistics.mean(lat), 1) if lat else None,
           "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1) if lat else None,
           "max_ms": round(lat[-1], 1) if lat else None}
    print(json.dumps(out))
    return 0 if counts["bad"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

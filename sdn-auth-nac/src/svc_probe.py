#!/usr/bin/env python3
"""Probe a protected service. Exit 0 on success, 1 on failure/timeout."""
import argparse, socket, sys, time

from common import DATA_PORT, PROTECTED_IP, WEB_PORT


def probe(host, port, nbytes=0, timeout=2.0, mode=None):
    mode = mode or ("web" if port == WEB_PORT else "data" if port == DATA_PORT else "connect")
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    connect_ms = (time.time() - t0) * 1000
    try:
        s.settimeout(max(timeout, 30) if nbytes else timeout)
        if mode == "web":
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                data += c
            ok = b"200" in data.split(b"\r\n")[0]
            return {"ok": ok, "connect_ms": round(connect_ms, 1), "total_ms": round((time.time() - t0) * 1000, 1)}
        if mode == "data":
            t1 = time.time()
            payload = b"x" * 65536
            sent = 0
            while sent < nbytes:
                n = min(len(payload), nbytes - sent)
                s.sendall(payload[:n])
                sent += n
            s.shutdown(socket.SHUT_WR)
            resp = s.recv(64).decode().strip()
            dt = time.time() - t1
            return {"ok": resp == "OK %d" % nbytes, "connect_ms": round(connect_ms, 1),
                    "mbps": round(nbytes * 8 / dt / 1e6, 1) if nbytes else 0}
        return {"ok": True, "connect_ms": round(connect_ms, 1)}
    except OSError as e:
        return {"ok": False, "error": str(e)}
    finally:
        s.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default=PROTECTED_IP)
    ap.add_argument("port", type=int, nargs="?", default=WEB_PORT)
    ap.add_argument("--bytes", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--mode", choices=["web", "data", "connect"])
    a = ap.parse_args()
    r = probe(a.host, a.port, a.bytes, a.timeout, a.mode)
    print(("OK " if r["ok"] else "FAIL ") + " ".join("%s=%s" % kv for kv in r.items() if kv[0] != "ok"))
    sys.exit(0 if r["ok"] else 1)

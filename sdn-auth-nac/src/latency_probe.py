#!/usr/bin/env python3
"""Measures grant latency (login OK -> first successful access) and revocation
latency (logout OK -> first blocked connection). Prints JSON."""
import argparse, json, time

from common import AUTH_IP, PROTECTED_IP, WEB_PORT
from auth_client import AuthClient
from svc_probe import probe

ap = argparse.ArgumentParser()
ap.add_argument("--user", default="alice")
ap.add_argument("--password", default="alice123")
ap.add_argument("--max-wait", type=float, default=5.0)
a = ap.parse_args()

res = {}
c = AuthClient(AUTH_IP)
t_login = time.time()
res["login"] = c.login(a.user, a.password)
t0 = time.time()
r = probe(PROTECTED_IP, WEB_PORT, timeout=3)
res["first_access_ok"] = r["ok"]
res["first_access_ms"] = round((time.time() - t0) * 1000, 1)
res["login_to_access_ms"] = round((time.time() - t_login) * 1000, 1)

t_logout = time.time()
res["logout"] = c.request("LOGOUT")
c.close()
res["revoked"] = False
while time.time() - t_logout < a.max_wait:
    t_try = time.time()
    if not probe(PROTECTED_IP, WEB_PORT, timeout=0.3)["ok"]:
        res["revoked"] = True
        res["revocation_ms"] = round((t_try - t_logout) * 1000, 1)
        break
    time.sleep(0.02)
print(json.dumps(res))

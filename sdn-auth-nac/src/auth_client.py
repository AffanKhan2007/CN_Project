#!/usr/bin/env python3
"""TCP authentication client. Example:
   python3 auth_client.py --host 10.0.0.4 --user alice --password alice123 --actions login,status,logout
"""
import argparse, socket, sys, time

from common import AUTH_IP, AUTH_PORT, challenge_response, pw_hash


class AuthClient:
    def __init__(self, host, port=AUTH_PORT, timeout=5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.f = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self.banner = self._recv()

    def _recv(self):
        line = self.f.readline()
        if not line:
            raise ConnectionError("server closed connection")
        return line.strip()

    def _send(self, msg):
        self.sock.sendall((msg + "\n").encode())

    def request(self, msg):
        self._send(msg)
        return self._recv()

    def login(self, user, password):
        resp = self.request("LOGIN " + user)
        if not resp.startswith("CHALLENGE "):
            return resp
        nonce = resp.split()[1]
        return self.request("RESPONSE " + challenge_response(pw_hash(password), nonce))

    def close(self):
        try:
            self._send("QUIT")
        except OSError:
            pass
        self.sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=AUTH_IP)
    ap.add_argument("--port", type=int, default=AUTH_PORT)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--actions", default="login", help="comma list: login,status,renew,logout,sleep:N")
    ap.add_argument("--timeout", type=float, default=5)
    a = ap.parse_args()
    rc = 0
    try:
        c = AuthClient(a.host, a.port, a.timeout)
        for act in a.actions.split(","):
            t0 = time.time()
            if act == "login":
                resp = c.login(a.user, a.password)
            elif act.startswith("sleep:"):
                time.sleep(float(act.split(":")[1]))
                continue
            elif act in ("status", "renew", "logout"):
                resp = c.request(act.upper())
            else:
                print("unknown action", act)
                return 2
            print("%s -> %s (%.1f ms)" % (act, resp, (time.time() - t0) * 1000))
            if not resp.startswith("OK"):
                rc = 1
        c.close()
    except (OSError, ConnectionError) as e:
        print("ERROR:", e)
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

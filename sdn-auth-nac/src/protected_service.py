#!/usr/bin/env python3
"""Protected services (runs on h5): HTTP on 8080, TCP data sink on 9090."""
import argparse, socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import DATA_PORT, WEB_PORT, get_logger

log = get_logger("protected", "protected.log")


class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"PROTECTED WEB RESOURCE - you are authenticated\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log.info("web %s %s", self.client_address[0], fmt % args)


def data_conn(conn, addr):
    conn.settimeout(30)
    total = 0
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            total += len(chunk)
        conn.sendall(("OK %d\n" % total).encode())
    except OSError:
        pass
    finally:
        conn.close()
    log.info("data %s received %d bytes", addr[0], total)


def data_server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, a = s.accept()
        threading.Thread(target=data_conn, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--web-port", type=int, default=WEB_PORT)
    ap.add_argument("--data-port", type=int, default=DATA_PORT)
    a = ap.parse_args()
    threading.Thread(target=data_server, args=(a.data_port,), daemon=True).start()
    log.info("protected services up: web=%d data=%d", a.web_port, a.data_port)
    ThreadingHTTPServer(("0.0.0.0", a.web_port), Web).serve_forever()

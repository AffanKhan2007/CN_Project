#!/usr/bin/env python3
"""
Mininet topology for the SDN authentication / access-control project.

   h1 (alice) --\\                                   /-- h4  auth server   10.0.0.4
   h2 (bob)   ---- s1 ======== s2 -----------------+--- h5  protected svc  10.0.0.5
   h3 (guest) --/                 \\
   h6 (attacker)/                  \\-- root namespace (Ryu controller)  10.0.0.254

Usage:  sudo python3 topology/topo.py [--ttl 60] [--cli]
(start the controller first:  ryu-manager src/controller.py)
"""
import argparse, os, sys, time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "src")
LOGS = os.path.join(BASE, "logs")
sys.path.insert(0, SRC)
from common import AUTH_IP, CTRL_IP, PROTECTED_IP  # noqa: E402

HOST_IPS = {"h1": "10.0.0.1", "h2": "10.0.0.2", "h3": "10.0.0.3",
            "h4": AUTH_IP, "h5": PROTECTED_IP, "h6": "10.0.0.6"}


def build_network(ctrl_ip="127.0.0.1", ctrl_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, waitConnected=False)
    net.addController("c0", controller=RemoteController, ip=ctrl_ip, port=ctrl_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    h = {n: net.addHost(n, ip=ip + "/24") for n, ip in HOST_IPS.items()}
    for n in ("h1", "h2", "h3", "h6"):
        net.addLink(h[n], s1, bw=100)
    net.addLink(s1, s2, bw=100)
    net.addLink(h["h4"], s2, bw=100)
    net.addLink(h["h5"], s2, bw=100)
    # root namespace attached to s2 so the auth server can reach the controller's event channel
    root = Node("root", inNamespace=False)
    intf = net.addLink(root, s2).intf1
    root.setIP(CTRL_IP + "/24", intf=intf)
    return net


def start_services(net, ttl=60, block_secs=30, max_fails=3):
    os.makedirs(LOGS, exist_ok=True)
    net["h5"].cmd("python3 -u %s/protected_service.py > %s/protected.out 2>&1 &" % (SRC, LOGS))
    net["h4"].cmd("python3 -u %s/auth_server.py --ttl %d --block-secs %d --max-fails %d > %s/auth.out 2>&1 &"
                  % (SRC, ttl, block_secs, max_fails, LOGS))
    time.sleep(1.5)


def stop_services(net):
    net["h4"].cmd("pkill -f auth_server.py")
    net["h5"].cmd("pkill -f protected_service.py")


def wait_for_switches(net, timeout=15):
    try:
        net.waitConnected(timeout=timeout)
    except Exception:
        time.sleep(4)
    time.sleep(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctrl-ip", default="127.0.0.1")
    ap.add_argument("--ctrl-port", type=int, default=6653)
    ap.add_argument("--ttl", type=int, default=60)
    ap.add_argument("--block-secs", type=int, default=30)
    ap.add_argument("--max-fails", type=int, default=3)
    ap.add_argument("--cli", action="store_true", default=True)
    a = ap.parse_args()
    setLogLevel("info")
    net = build_network(a.ctrl_ip, a.ctrl_port)
    net.start()
    wait_for_switches(net)
    start_services(net, a.ttl, a.block_secs, a.max_fails)
    info("*** Ready. Try on h1:  python3 src/auth_client.py --user alice --password alice123 --actions login,status\n")
    CLI(net)
    stop_services(net)
    net.stop()

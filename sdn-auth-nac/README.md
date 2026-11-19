# SDN-Socket Programming (Jackfruit) — Problem 2: Authentication and Network Access Control

A TCP authentication service where hosts must log in before they can reach a protected server.
A Ryu (OpenFlow 1.3) controller **dynamically installs, restricts and removes flow rules** based on
authentication events coming from the auth server.

## 1. Architecture

```
 h1 alice(admin)  ─┐                                      ┌─ h4  AUTH SERVER   10.0.0.4:9000  (TCP sockets)
 h2 bob  (user)   ─┼─ s1 ═══════════ s2 ──────────────────┼─ h5  PROTECTED     10.0.0.5  web:8080  data:9090
 h3 guest(guest)  ─┤  (OVS, OF1.3)   (OVS, OF1.3)         └─ root ns: Ryu controller 10.0.0.254
 h6 attacker      ─┘                                           ├─ OpenFlow :6653  (switches)
                                                              └─ event channel :9100  (auth server only)
```

**Communication flow**
1. Client opens TCP to `10.0.0.4:9000` (always allowed by the baseline flows) and logs in with challenge–response.
2. Auth server verifies the HMAC, then sends `GRANT{ip,user,role,ttl}` to the controller (TCP :9100) and **waits for the ACK** (fail-closed).
3. Controller installs per-client, per-service flows (both directions) with `hard_timeout = session TTL`.
4. `LOGOUT`, timeout or brute-force detection → `REVOKE` / `BLOCK` events → controller deletes the flows / installs a drop rule.
5. Anything not explicitly allowed is sent to the controller (packet-in), logged as `DENY`, and a 10 s drop flow is installed so the controller isn't flooded.

### Authentication protocol (TCP :9000, line based)
```
S: HELLO sdn-auth/1.0
C: LOGIN alice            S: CHALLENGE <nonce>
C: RESPONSE <HMAC-SHA256(key=sha256(password), msg=nonce)>
                          S: OK <token> <role> <ttl>   |  FAIL bad_credentials | FAIL blocked <s>
C: STATUS | RENEW | LOGOUT | QUIT
```
The password never crosses the wire; a nonce prevents replay; unknown users get a challenge too (no user enumeration).
The session is bound to the client's source IP.

### Roles / policies (`config/config.json`)
| Role  | Users        | Allowed to protected host h5 |
|-------|--------------|------------------------------|
| admin | alice        | everything (`*`)             |
| user  | bob, carol   | ICMP + web (tcp/8080)        |
| guest | guest        | web only (tcp/8080)          |

Users: `alice/alice123`, `bob/bob123`, `carol/carol123`, `guest/guest123` (stored as SHA-256 in `config/users.json`).

### Flow table (table 0)
| Prio | Purpose | Timeout |
|---|---|---|
| 300 | BLOCK – drop everything from a brute-forcing IP | hard = block time |
| 200 | ALLOW – client⇄h5 per service/role | hard = session TTL |
| 150 | DENY – drop a denied (src,dst,proto,port); logged once | idle 10 s |
| 110/100 | INFRA – auth server ⇄ controller; anyone → auth :9000 + ICMP | – |
| 90 | GUARD – hosts can never talk to the controller IP | – |
| 50 | generic east-west traffic (reactive, `NORMAL`) | idle 30 s |
| 10 | ARP → `NORMAL` | – |
| 0 | table-miss → controller | – |

Forwarding uses OVS's `NORMAL` action (L2 learning), so the controller's job is purely **policy** (who may talk to what).

## 2. Requirement ↔ implementation map
| Requirement | Where |
|---|---|
| TCP auth server + clients | `src/auth_server.py`, `src/auth_client.py` |
| Multiple concurrent users | thread-per-connection server; `src/auth_stress.py`, test T7 |
| Sessions + timeouts | server reaper + flow `hard_timeout`, `RENEW`; test T5 |
| Allow/deny policies | role table in `config.json`, `controller.py::_permitted`; tests T1, T3 |
| Dynamic install/remove of SDN rules | `_grant`, `_revoke`, `_block`; tests T2, T4, T6 |
| Auth + access logs | `logs/auth.log`, `logs/access.log` (GRANT/REVOKE/BLOCK/LOGIN_FAIL), `logs/controller.log` (ALLOW/DENY/flow-mods), `logs/flow_stats.csv` |
| Authorized & unauthorized scenarios | `tests/run_tests.py` |

Robustness scenarios: brute-force → automatic network-level block; auth server fail-closed if controller is down;
controller unreachable from hosts; session expiry; role downgrade/upgrade on re-login.

## 3. Setup (Ubuntu 20.04 VM recommended)
```bash
sudo apt install mininet openvswitch-switch python3-pip
pip3 install -r requirements.txt        # ryu 4.34 + eventlet 0.30.2
```
Ryu is old: it works best on Python 3.8/3.9. On newer Pythons, `pip install ryu` or `ryu-manager` commonly breaks
(eventlet / setuptools incompatibilities) — use a 20.04 VM or a venv with Python 3.8/3.9.
Make sure nothing else uses `10.0.0.0/24` on the VM.

## 4. Run the demo
```bash
# terminal 1 – controller
ACL_MODE=dynamic ryu-manager src/controller.py
# terminal 2 – network (starts auth server on h4 and protected services on h5), opens Mininet CLI
sudo python3 topology/topo.py --ttl 60
```
In the Mininet CLI:
```
h6 python3 src/svc_probe.py 10.0.0.5 8080                   # FAIL  (not authenticated)
h1 python3 src/auth_client.py --user alice --password alice123 --actions login,status
h1 python3 src/svc_probe.py 10.0.0.5 8080                   # OK
h1 ping -c2 10.0.0.5                                         # OK  (admin)
h3 python3 src/auth_client.py --user guest --password guest123
h3 python3 src/svc_probe.py 10.0.0.5 9090                   # FAIL (guest: web only)
h1 python3 src/auth_client.py --user alice --password alice123 --actions login,logout
h1 python3 src/svc_probe.py 10.0.0.5 8080                   # FAIL (revoked)
sh ovs-ofctl -O OpenFlow13 dump-flows s1                     # watch rules appear / disappear
```
Watch live: `tail -f logs/access.log logs/controller.log`.

## 5. Automated tests
```bash
sudo RYU=$HOME/ryu-env/bin/ryu-manager ./scripts/run_tests.sh      # starts controller, runs 8 test groups, prints PASS/FAIL, saves results/functional_tests.json
```

## 6. Performance evaluation & baselines
`ACL_MODE` selects what the controller does, so the same topology/workload is compared against two baselines:
* **dynamic** – proposed: authentication drives the flow table
* **static** – baseline 1: fixed IP allow-list pre-installed (`static_allowed_ips`), auth ignored
* **open** – baseline 2: no access control

```bash
sudo RYU=$HOME/ryu-env/bin/ryu-manager ./scripts/run_all_experiments.sh    # → results/perf_*.json, results/comparison.md, results/comparison.png
```
Metrics: login latency (sequential and 20 concurrent clients), login→first-access (grant) latency,
logout→blocked (revocation) latency, TCP throughput (50 MB × 3) and ping RTT after authentication,
and a security matrix (unauthenticated access, authenticated-but-unlisted host, least privilege).
Paste the generated table into your report and discuss it (expected shape: dynamic ≈ static on data-plane
throughput/RTT because flows are proactive; dynamic adds ms-scale grant latency but is the only one that revokes,
enforces roles and admits hosts not known in advance — confirm with *your* measurements).

## 7. Limitations (mention in viva)
* Sessions are bound to source IP/MAC-learning by OVS; IP spoofing is not prevented (could add `in_port`/`eth_src` binding).
* Passwords are verified by challenge–response but the channel is not encrypted (no TLS) and the credential store is a hash file.
* Single controller, no HA; if the controller is down new logins fail (fail-closed) while installed flows keep working until they time out.
* Session state in the controller is in-memory (lost on restart; flows time out by themselves).

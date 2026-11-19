#!/usr/bin/env bash
# Usage:  sudo RYU=$HOME/ryu-env/bin/ryu-manager ./scripts/NAME.sh
set -e
RYU="${RYU:-ryu-manager}"; PY="${PY:-/usr/bin/python3}"
cd "$(dirname "$0")/.."
mn -c >/dev/null 2>&1 || true
: > logs/access.log; : > logs/auth.log; : > logs/controller.log
ACL_MODE=dynamic $RYU --ofp-tcp-listen-port 6653 src/controller.py > logs/ryu_dynamic.out 2>&1 &
RYU_PID=$!
sleep 5
$PY tests/run_tests.py || RC=$?
kill $RYU_PID 2>/dev/null || true
mn -c >/dev/null 2>&1 || true
exit ${RC:-0}

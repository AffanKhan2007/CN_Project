#!/usr/bin/env bash
# Runs the performance experiment for open / static / dynamic modes and builds the comparison table.
# Usage:  sudo RYU=$HOME/ryu-env/bin/ryu-manager ./scripts/NAME.sh
set -e
RYU="${RYU:-ryu-manager}"; PY="${PY:-/usr/bin/python3}"
cd "$(dirname "$0")/.."
for mode in open static dynamic; do
  echo "=== mode: $mode ==="
  mn -c >/dev/null 2>&1 || true
  ACL_MODE=$mode $RYU --ofp-tcp-listen-port 6653 src/controller.py > logs/ryu_$mode.out 2>&1 &
  RYU_PID=$!
  sleep 5
  $PY tests/run_perf.py --mode $mode
  kill $RYU_PID 2>/dev/null || true
  wait $RYU_PID 2>/dev/null || true
  mn -c >/dev/null 2>&1 || true
done
python3 tools/compare.py

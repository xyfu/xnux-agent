#!/usr/bin/env bash
# Resource envelope check for xnux-agent (F1-9): runs the agent against a
# local fake ingest endpoint and verifies resident memory and idle CPU.
#
#   DURATION=120 scripts/agent-resource-check.sh
#
# Thresholds: RSS < 15 MB at every sample; average CPU < MAX_CPU_PCT
# (default 0.05%, which top rounds to 0.00% or 0.01% on one core).
set -euo pipefail

DURATION=${DURATION:-120}
WARMUP=${WARMUP:-15}
MAX_RSS_KB=${MAX_RSS_KB:-15360}
MAX_CPU_PCT=${MAX_CPU_PCT:-0.05}
PORT=${PORT:-18091}

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
cleanup() { kill "${agent_pid:-}" "${srv_pid:-}" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$work/xnux-agent" ./cmd/xnux-agent)

python3 - "$PORT" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(202); self.end_headers(); self.wfile.write(b'{"ack_seq":0,"server_time":0}')
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
srv_pid=$!

cat > "$work/agent.yaml" <<YAML
token: "xat_resourcecheck00000000000000"
endpoint: "http://127.0.0.1:$PORT"
interval_seconds: 15
flush_seconds: 60
YAML
chmod 600 "$work/agent.yaml"

"$work/xnux-agent" --config "$work/agent.yaml" --state-dir "$work/lib" --log-dir "$work/log" &
agent_pid=$!
sleep "$WARMUP"

# CPU time in ns from schedstat (all threads), which is far finer than the
# 10 ms clock ticks in /proc/<pid>/stat.
cpu_ns() {
  local sum=0 t
  for t in /proc/"$agent_pid"/task/*/schedstat; do
    sum=$(( sum + $(awk '{print $1}' "$t") ))
  done
  echo "$sum"
}
rss() { awk '/^VmRSS:/ {print $2}' "/proc/$agent_pid/status"; }

t0=$(date +%s.%N); c0=$(cpu_ns); max_rss=0
end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
  r=$(rss); [ "$r" -gt "$max_rss" ] && max_rss=$r
  sleep 5
done
t1=$(date +%s.%N); c1=$(cpu_ns)

cpu=$(awk -v c0="$c0" -v c1="$c1" -v t0="$t0" -v t1="$t1" 'BEGIN { printf "%.4f", (c1-c0)/1e9/(t1-t0)*100 }')
cpu_ms=$(awk -v c0="$c0" -v c1="$c1" 'BEGIN { printf "%.1f", (c1-c0)/1e6 }')
hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$agent_pid/status")
echo "duration=${DURATION}s  max VmRSS=${max_rss} kB  VmHWM=${hwm} kB  CPU time=${cpu_ms} ms  avg CPU=${cpu}%"

fail=0
[ "$max_rss" -lt "$MAX_RSS_KB" ] || { echo "FAIL: RSS ${max_rss} kB >= ${MAX_RSS_KB} kB"; fail=1; }
awk -v c="$cpu" -v m="$MAX_CPU_PCT" 'BEGIN { exit !(c < m) }' || { echo "FAIL: CPU ${cpu}% >= ${MAX_CPU_PCT}%"; fail=1; }
grep -q '"agent started"' "$work/log/agent.log" || { echo "FAIL: agent did not start"; cat "$work/log/agent.log"; fail=1; }
exit $fail

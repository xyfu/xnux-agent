#!/usr/bin/env bash
# Runs deploy/install.sh against the binaries in bin/ (make dist) inside a
# distro container, with no server: dry-run as an unprivileged user installs
# nothing and prints the payload, a binary that does not match
# SHA256SUMS is refused, and a standalone install (no token, no systemd)
# answers the xnux CLI and uninstalls cleanly. The full install against the service runs in the
# service's own CI.
#
#   make dist && IMAGE=ubuntu:24.04 scripts/install-smoke.sh
set -euo pipefail

IMAGE=${IMAGE:-ubuntu:24.04}
root=$(cd "$(dirname "$0")/.." && pwd)
name="xnux-smoke-$$"
evil=$(mktemp -d)
good_pid='' evil_pid=''
# shellcheck disable=SC2317,SC2329 # invoked by the trap
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
	[ -z "$good_pid" ] || kill "$good_pid" "$evil_pid" 2>/dev/null || true
	rm -rf "$evil"
}
trap cleanup EXIT

for a in amd64 arm64; do printf 'not the agent' >"$evil/xnux-agent-linux-$a"; done
cp "$root/bin/SHA256SUMS" "$evil/"

# The release files, and a tampered copy, served over HTTP on the host.
port=$((20000 + $$ % 10000))
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$root/bin" >/dev/null 2>&1 &
good_pid=$!
python3 -m http.server $((port + 1)) --bind 127.0.0.1 --directory "$evil" >/dev/null 2>&1 &
evil_pid=$!
sleep 1

docker run -d --name "$name" --network host "$IMAGE" sleep infinity >/dev/null
x() { docker exec "$name" sh -c "$1"; }
if ! x 'command -v curl || command -v wget' >/dev/null; then
	x '(apt-get update -qq && apt-get install -y -qq curl) >/dev/null 2>&1 || dnf install -y -q curl >/dev/null 2>&1 || apk add -q curl'
fi
docker cp "$root/bin/install.sh" "$name:/tmp/i.sh"
docker cp "$root/bin/uninstall.sh" "$name:/tmp/u.sh"
x 'chmod 755 /tmp/i.sh /tmp/u.sh'

fails=0
out=$(x "su -s /bin/sh nobody -c 'sh /tmp/i.sh --dry-run --base-url http://127.0.0.1:$port' 2>&1" || true)
if printf '%s' "$out" | grep -q 'sha256 verified' && printf '%s' "$out" | grep -q '"agent_version"' &&
	! x 'test -e /usr/local/bin/xnux-agent -o -e /etc/xnux'; then
	echo "PASS dry-run as nobody printed the payload and installed nothing"
else
	echo "FAIL dry-run: $(printf '%s' "$out" | tail -5)"
	fails=$((fails + 1))
fi

out=$(x "sh /tmp/i.sh --token xat_0000000000000000000000 --base-url http://127.0.0.1:$((port + 1)) 2>&1" || true)
if printf '%s' "$out" | grep -q 'sha256 mismatch' && ! x 'test -e /usr/local/bin/xnux-agent -o -e /etc/xnux'; then
	echo "PASS a binary that does not match SHA256SUMS is refused"
else
	echo "FAIL tampered binary: $(printf '%s' "$out" | tail -3)"
	fails=$((fails + 1))
fi
# Standalone: no token, no systemd in the container, the agent run by hand.
out=$(x "sh /tmp/i.sh --no-prompt --base-url http://127.0.0.1:$port 2>&1" || true)
x 'nohup /usr/local/bin/xnux-agent run >/dev/null 2>&1 &'
status=''
for _ in $(seq 1 20); do
	status=$(x 'xnux status --json 2>/dev/null' || true)
	case "$status" in *standalone*) break ;; esac
	sleep 1
done
if x 'test -L /usr/local/bin/xnux && test -f /etc/xnux/agent.yaml' && ! x 'grep -q "^token:" /etc/xnux/agent.yaml' &&
	printf '%s' "$status" | grep -q '"mode": *"standalone"'; then
	echo "PASS standalone install answers xnux status"
else
	echo "FAIL standalone: $(printf '%s' "$out" | tail -3) / $status"
	fails=$((fails + 1))
fi
# shellcheck disable=SC2016 # expanded inside the container
x 'pid=$(grep -lx xnux-agent /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3); [ -z "$pid" ] || kill "$pid"'
x 'sh /tmp/u.sh --purge >/dev/null 2>&1' || true
if ! x 'test -e /usr/local/bin/xnux-agent -o -e /usr/local/bin/xnux -o -e /etc/xnux -o -e /var/lib/xnux' &&
	! x 'getent group xnux >/dev/null'; then
	echo "PASS uninstall --purge removed binary, CLI, config, state and group"
else
	echo "FAIL uninstall left files behind"
	fails=$((fails + 1))
fi
exit "$fails"

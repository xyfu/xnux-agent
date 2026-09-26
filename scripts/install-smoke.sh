#!/usr/bin/env bash
# Runs deploy/install.sh against the binaries in bin/ (make dist) inside a
# distro container, with no server: dry-run as an unprivileged user installs
# nothing and prints the payload, and a binary that does not match
# SHA256SUMS is refused. The full install against the service runs in the
# service's own CI.
#
#   make dist && IMAGE=ubuntu:24.04 scripts/install-smoke.sh
set -euo pipefail

IMAGE=${IMAGE:-ubuntu:24.04}
root=$(cd "$(dirname "$0")/.." && pwd)
name="xnux-smoke-$$"
evil=$(mktemp -d)
good_pid='' evil_pid=''
# shellcheck disable=SC2329 # invoked by the trap
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
x 'chmod 755 /tmp/i.sh'

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
exit "$fails"

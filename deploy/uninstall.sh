#!/bin/sh
# Removes the Xnux agent installed by install.sh.
#
#   curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/uninstall.sh | sudo sh
#   … | sudo sh -s -- --purge     # also delete config, state, logs and the xnux user
set -eu

PURGE=0
case "${1:-}" in
--purge) PURGE=1 ;;
"") ;;
-h | --help)
	echo "Usage: uninstall.sh [--purge]"
	exit 0
	;;
*)
	echo "xnux: unknown option: $1" >&2
	exit 1
	;;
esac

[ "$(id -u)" = 0 ] || {
	echo "xnux: run as root" >&2
	exit 1
}

if [ -d /run/systemd/system ] && systemctl list-unit-files xnux-agent.service >/dev/null 2>&1; then
	systemctl disable --now xnux-agent.service >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/xnux-agent.service
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
rm -f /usr/local/bin/xnux-agent
echo "xnux: agent stopped and removed"

if [ "$PURGE" = 1 ]; then
	rm -rf /etc/xnux /var/lib/xnux /var/log/xnux
	if id xnux >/dev/null 2>&1; then userdel xnux 2>/dev/null || deluser xnux 2>/dev/null || true; fi
	echo "xnux: config, state and logs deleted"
else
	echo "xnux: kept /etc/xnux, /var/lib/xnux and /var/log/xnux (use --purge to delete them)"
fi
echo "xnux: delete the server in the console too, so its data is removed and its token revoked"

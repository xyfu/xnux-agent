#!/bin/sh
# Xnux agent installer (spec F7-2, A8.4). Source: https://github.com/xyfu/xnux-agent
#
#   curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/install.sh | sudo sh -s -- --token xat_…
#
# Downloads the static xnux-agent for this machine's architecture, refuses
# to install it unless its sha256 matches the release's SHA256SUMS, writes
# /etc/xnux/agent.yaml and a hardened systemd unit, and starts the agent.
# Re-running it upgrades the binary and keeps the existing configuration.
# There is no self-update: upgrades only ever happen by running this again.
set -eu

REPO="xyfu/xnux-agent"
BIN=/usr/local/bin/xnux-agent
CONF_DIR=/etc/xnux
CONF="$CONF_DIR/agent.yaml"
UNIT=/etc/systemd/system/xnux-agent.service

TOKEN=""
ENDPOINT=""
VERSION="latest"
BASE_URL=""
DRY_RUN=0
HIDE_HOSTNAME=0
CA_FILE=""
LEAST_PRIV=0
NO_START=0

usage() {
	cat <<'EOF'
Usage: install.sh --token TOKEN [options]

  --token TOKEN        agent token from the console (xat_…); optional when upgrading
  --endpoint URL       where to send data: the server, or your Cloudflare Worker
                       (default https://ingest.xnux.net)
  --version vX.Y.Z     release to install (default: latest)
  --base-url URL       download binaries from here instead of GitHub Releases
                       (a mirror of the release files, e.g. https://<server>/dl)
  --dry-run            download and verify, then show what the agent would send
                       (xnux-agent --dry-run --once); installs nothing
  --hide-hostname      report the hostname as "host"
  --ca-file PATH       trust this CA for the endpoint (a private CA)
  --least-privilege    run as the unprivileged "xnux" user with only the
                       capabilities it needs, instead of root
  --no-start           install but do not start the service
  -h, --help           this help
EOF
}

say() { printf '%s\n' "xnux: $*"; }
die() {
	printf '%s\n' "xnux: error: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--token) TOKEN="${2:-}"; shift 2 ;;
	--token=*) TOKEN="${1#*=}"; shift ;;
	--endpoint) ENDPOINT="${2:-}"; shift 2 ;;
	--endpoint=*) ENDPOINT="${1#*=}"; shift ;;
	--version) VERSION="${2:-}"; shift 2 ;;
	--version=*) VERSION="${1#*=}"; shift ;;
	--base-url) BASE_URL="${2:-}"; shift 2 ;;
	--base-url=*) BASE_URL="${1#*=}"; shift ;;
	--ca-file) CA_FILE="${2:-}"; shift 2 ;;
	--ca-file=*) CA_FILE="${1#*=}"; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	--hide-hostname) HIDE_HOSTNAME=1; shift ;;
	--least-privilege) LEAST_PRIV=1; shift ;;
	--no-start) NO_START=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
done

# ---- checks ----------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "xnux-agent runs on Linux only"
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m) (amd64 and arm64 are available)" ;;
esac

# Values end up in YAML and a unit file: accept only what they can be.
if [ -n "$TOKEN" ]; then
	printf '%s' "$TOKEN" | grep -Eq '^xat_[A-Za-z0-9_-]{16,128}$' || die "that does not look like an agent token (xat_…)"
fi
if [ -n "$ENDPOINT" ]; then
	printf '%s' "$ENDPOINT" | grep -Eq '^https?://[A-Za-z0-9.:%_~/[-]+$' || die "--endpoint must be an http(s) URL"
	ENDPOINT="${ENDPOINT%/}"
fi
printf '%s' "$VERSION" | grep -Eq '^(latest|v[0-9A-Za-z.+-]+)$' || die "--version must look like v1.2.3"
if [ -n "$CA_FILE" ]; then
	[ -r "$CA_FILE" ] || die "cannot read $CA_FILE"
	printf '%s' "$CA_FILE" | grep -Eq '^/[A-Za-z0-9._/-]+$' || die "--ca-file must be an absolute path without spaces"
fi
if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" != 0 ]; then
	die "run as root (sudo sh -s -- …), or add --dry-run to only preview"
fi
if [ "$DRY_RUN" = 1 ] && [ -z "$TOKEN" ]; then
	TOKEN="xat_dryrun_preview_only_0000"
fi
if [ "$DRY_RUN" = 0 ] && [ -z "$TOKEN" ] && [ ! -f "$CONF" ]; then
	die "--token is required for a new installation"
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=http,https' --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
	sha256() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
else
	die "sha256sum, shasum or openssl is required to verify the download"
fi

# ---- download and verify ---------------------------------------------------

if [ -z "$BASE_URL" ]; then
	if [ "$VERSION" = latest ]; then
		BASE_URL="https://github.com/$REPO/releases/latest/download"
	else
		BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
	fi
fi
BASE_URL="${BASE_URL%/}"
NAME="xnux-agent-linux-$ARCH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $NAME from $BASE_URL"
fetch "$BASE_URL/$NAME" "$TMP/$NAME" || die "download failed: $BASE_URL/$NAME"
fetch "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: $BASE_URL/SHA256SUMS"

WANT="$(awk -v f="$NAME" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")"
[ -n "$WANT" ] || die "SHA256SUMS has no entry for $NAME"
GOT="$(sha256 "$TMP/$NAME")"
[ "$WANT" = "$GOT" ] || die "sha256 mismatch for $NAME: expected $WANT, got $GOT — not installing"
say "sha256 verified: $GOT"
chmod 0755 "$TMP/$NAME"
"$TMP/$NAME" version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"

# ---- config ----------------------------------------------------------------

write_config() { # $1 = path
	umask 077
	{
		echo "# Written by install.sh; see https://github.com/$REPO/blob/main/deploy/agent.yaml.example"
		echo "token: \"$TOKEN\""
		echo "endpoint: \"${ENDPOINT:-https://ingest.xnux.net}\""
		if [ "$HIDE_HOSTNAME" = 1 ]; then echo "hide_hostname: true"; fi
		if [ -n "$CA_FILE" ]; then
			echo "tls:"
			echo "  ca_file: \"$CA_FILE\""
		fi
	} >"$1"
	chmod 0600 "$1"
}

if [ "$DRY_RUN" = 1 ]; then
	write_config "$TMP/agent.yaml"
	say "dry run: collecting one round; nothing is sent and nothing is installed"
	"$TMP/$NAME" --dry-run --once --config "$TMP/agent.yaml" --state-dir "$TMP/state" --log-dir "$TMP/log"
	exit 0
fi

install -d -m 0755 "$(dirname "$BIN")"
install -m 0755 "$TMP/$NAME" "$BIN.new"
mv -f "$BIN.new" "$BIN"
say "installed $BIN ($("$BIN" version))"

install -d -m 0700 "$CONF_DIR"
if [ ! -f "$CONF" ]; then
	write_config "$CONF"
	say "wrote $CONF"
else
	# Upgrade: keep the user's config, only replace what was passed.
	cp -p "$CONF" "$CONF.bak"
	if [ -n "$TOKEN" ]; then
		sed -i "s|^token:.*|token: \"$TOKEN\"|" "$CONF"
	fi
	if [ -n "$ENDPOINT" ]; then
		if grep -q '^endpoint:' "$CONF"; then
			sed -i "s|^endpoint:.*|endpoint: \"$ENDPOINT\"|" "$CONF"
		else
			echo "endpoint: \"$ENDPOINT\"" >>"$CONF"
		fi
	fi
	if [ "$HIDE_HOSTNAME" = 1 ]; then
		if grep -q '^hide_hostname:' "$CONF"; then
			sed -i 's|^hide_hostname:.*|hide_hostname: true|' "$CONF"
		else
			echo "hide_hostname: true" >>"$CONF"
		fi
	fi
	chmod 0600 "$CONF"
	say "kept $CONF (previous copy in $CONF.bak)"
fi

# ---- service ---------------------------------------------------------------

if [ ! -d /run/systemd/system ]; then
	say "systemd is not running here: service-crash monitoring stays off, and the agent is not started for you."
	say "run it under your init system, e.g.:  $BIN run --config $CONF"
	exit 0
fi

SYSTEMD_VER="$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 + 0 }')"
SYSTEMD_VER="${SYSTEMD_VER:-0}"

GROUPS_LINE=""
if [ "$LEAST_PRIV" = 1 ]; then
	# AmbientCapabilities= arrived in systemd 229.
	[ "$SYSTEMD_VER" -ge 229 ] || die "--least-privilege needs systemd 229 or newer (this host has $SYSTEMD_VER)"
	if ! id xnux >/dev/null 2>&1; then
		NOLOGIN="$(command -v nologin || echo /bin/false)"
		useradd --system --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" xnux 2>/dev/null ||
			adduser --system --no-create-home --home /nonexistent --shell "$NOLOGIN" xnux ||
			die "could not create the xnux user"
	fi
	chown xnux "$CONF_DIR" "$CONF"
	for g in systemd-journal adm; do
		if getent group "$g" >/dev/null 2>&1; then GROUPS_LINE="$GROUPS_LINE $g"; fi
	done
else
	chown root "$CONF_DIR" "$CONF" 2>/dev/null || true
fi

{
	cat <<'EOF'
[Unit]
Description=Xnux agent
Documentation=https://github.com/xyfu/xnux-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xnux-agent run --config /etc/xnux/agent.yaml
Restart=always
RestartSec=5
Environment=GOMAXPROCS=2 GOGC=50

# Hardening (spec A1).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/xnux /var/log/xnux
StateDirectory=xnux
LogsDirectory=xnux
MemoryMax=64M
CPUQuota=10%
EOF
	if [ "$LEAST_PRIV" = 1 ]; then
		echo ""
		echo "# Least-privilege mode (installed with --least-privilege)."
		echo "User=xnux"
		echo "Group=xnux"
		if [ -n "$GROUPS_LINE" ]; then echo "SupplementaryGroups=${GROUPS_LINE# }"; fi
		echo "AmbientCapabilities=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"
		echo "CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"
	fi
	cat <<'EOF'

[Install]
WantedBy=multi-user.target
EOF
} >"$UNIT.new"
chmod 0644 "$UNIT.new"
# Older systemd (CentOS 7, Ubuntu 16.04…) ignores the newer hardening keys:
# before 235 there is no StateDirectory/LogsDirectory, before 232 no
# ProtectSystem=strict, before 231 no ReadWritePaths/MemoryMax. Use the
# older equivalents and create the directories ourselves.
if [ "$SYSTEMD_VER" -lt 235 ]; then
	sed -i -e 's/^ProtectSystem=strict$/ProtectSystem=full/' \
		-e 's/^ReadWritePaths=/ReadWriteDirectories=/' \
		-e '/^StateDirectory=/d' -e '/^LogsDirectory=/d' \
		-e 's/^MemoryMax=/MemoryLimit=/' "$UNIT.new"
	install -d -m 0700 /var/lib/xnux /var/log/xnux
	if [ "$LEAST_PRIV" = 1 ]; then chown -R xnux:xnux /var/lib/xnux /var/log/xnux; fi
fi
mv -f "$UNIT.new" "$UNIT"
systemctl daemon-reload
systemctl enable xnux-agent.service >/dev/null 2>&1

if [ "$NO_START" = 1 ]; then
	say "installed; start it with: systemctl start xnux-agent"
	exit 0
fi
systemctl restart xnux-agent.service
sleep 2
if systemctl is-active --quiet xnux-agent.service; then
	say "xnux-agent is running"
else
	systemctl status --no-pager xnux-agent.service >&2 || true
	die "xnux-agent did not start; see: journalctl -u xnux-agent"
fi
"$BIN" --check --config "$CONF" || say "self-check reported problems (see above); the agent keeps retrying in the background"

UNINSTALL_URL="$BASE_URL/uninstall.sh"

cat <<EOF

  Preview what it sends:   sudo $BIN --dry-run --once
  What it sent last:       sudo cat /var/log/xnux/last_outgoing_payload.json
  Logs:                    journalctl -u xnux-agent
  Uninstall:               curl -fsSL $UNINSTALL_URL | sudo sh

EOF

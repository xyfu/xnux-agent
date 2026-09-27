# Least-privilege deployment

English | [简体中文](least-privilege.zh-CN.md)

By default the agent runs as root (still confined by the systemd sandbox: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, write access only to `/var/lib/xnux` and `/var/log/xnux`, a 64 MB memory limit, a 10% CPU limit). If you don't want any third-party program running as root, you can use a dedicated user with a minimal capability set.

## In one step

```sh
curl -fsSL …/install.sh | sudo sh -s -- --token xat_… --least-privilege
```

The script will:

1. Create the system user `xnux` (no home, no login shell).
2. Hand `/etc/xnux/agent.yaml` over to `xnux` (still 0600).
3. Add to the unit:

```ini
User=xnux
Group=xnux
SupplementaryGroups=systemd-journal adm     # only groups that exist on the system are added
AmbientCapabilities=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
```

systemd automatically hands `StateDirectory` / `LogsDirectory` over to `xnux`. On a machine that already has the agent installed, rerun the command with `--least-privilege` to switch; the config is kept.

## What each permission is for

| Permission | Used for | Without it |
| --- | --- | --- |
| `CAP_SYSLOG` | Reading `/dev/kmsg` | No OOM, segfault, disk error, read-only filesystem or hung task events |
| `CAP_DAC_READ_SEARCH` | Reading `/var/log/auth.log` and `/var/log/secure`; reading `/proc/<pid>/fd` of other users' processes | No SSH brute force / login breach / sudo events (unless the journal is used instead); the suspicious-process scan cannot see other users' processes |
| `CAP_SYS_PTRACE` | `readlink` on `/proc/<pid>/exe` of other users' processes | Cannot detect fileless processes, deleted executables or programs run from `/tmp` |
| `systemd-journal` group | Reading service log tails and auth logs through the journal | Service crash events have no log tail |

At startup the agent checks whether each collector actually works; unavailable ones are disabled automatically and removed from the reported `capabilities`, and the server detail page in the console shows which monitoring is missing. Resource metrics (CPU, memory, disk, load, temperature) need no privileges.

## Going further

- Resource monitoring only: turn off `collectors.kmsg`, `authlog` and `procscan` in `agent.yaml`, and remove all capabilities from the unit.
- Keep the hostname from appearing anywhere: `hide_hostname: true`.
- Keep the server from learning your origin IP: use the [Cloudflare Worker proxy](relay.md).
- Check exactly what it sends: [Transparency](../README.md#verify-it-yourself).

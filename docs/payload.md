# Payload fields

English | [简体中文](payload.zh-CN.md)

The agent makes exactly one kind of outbound request: `POST {endpoint}/v1/ingest`. The server's response contains only an acknowledged sequence number, the server time and optional hints (`agent_outdated`, `clock_skew`). It never carries instructions or configuration for the agent to execute: the agent does not accept remote commands.

Machine-readable definition: [proto/ingest.v1.schema.json](https://github.com/xyfu/xnux-shared/blob/main/proto/ingest.v1.schema.json) (JSON Schema, in the [xnux-shared](https://github.com/xyfu/xnux-shared) repository). To see what your own machine actually sends: `xnux-agent --dry-run --once`, or `/var/log/xnux/last_outgoing_payload.json`.

## Request

```http
POST /v1/ingest HTTP/1.1
Content-Type: application/json
Content-Encoding: gzip
Authorization: Bearer xat_…
User-Agent: xnux-agent/1.0.0 (linux; amd64)
X-Xnux-Seq: 10423
X-Xnux-Schema: 1
```

TLS ≥ 1.2 with certificate verification (there is no "skip verification" option; use `tls.ca_file` for a private CA). ≤ 512 KB compressed, ≤ 4 MB decompressed. By default the agent samples every 15 seconds and reports every 60 seconds; when an event occurs it reports immediately. Every string passes through the [redaction barrier](redaction.md) before sending.

## Top level

| Field | Description |
| --- | --- |
| `v` | Protocol version, always 1 |
| `seq` | Monotonically increasing sequence number; the server deduplicates on it (safe to resend) |
| `part` | Part number when an oversized payload is split |
| `sent_at` | Agent local time (Unix seconds) |
| `agent_version` | Agent version |
| `machine_fp` | First 16 characters of sha256(machine-id + token), used to detect "the same token copied to multiple machines" |
| `host` | Host information: included at startup, every 6 hours, and on change |
| `metrics[]` | Resource metrics, in ascending time order |
| `events[]` | Incident context events |
| `diag` | Agent self-diagnostics: `rss_mb`, `spool_mb`, `kmsg_lost`, `dropped_metrics`, `collector_errors` |
| `redactions` | Hit count for each redaction rule in this payload, e.g. `{"ipv4": 2}` |

## `host`

| Field | Source |
| --- | --- |
| `hostname` | Hostname; `host` when `hide_hostname: true` |
| `os` | `PRETTY_NAME` from `/etc/os-release` |
| `kernel`, `arch` | `uname` |
| `cores`, `uptime`, `virt` | CPU count, seconds since boot, virtualization type |
| `capabilities` | Collectors actually enabled: `metrics`, `temps`, `systemd`, `kmsg`, `authlog`, `procscan` |

Not collected: IP addresses, MAC addresses, network interface list, user list, installed software, file contents, environment variables.

## `metrics[]`

| Field | Contents |
| --- | --- |
| `ts` | Sample time |
| `cpu` | `total_pct`, `iowait_pct`, `steal_pct` |
| `load` | `l1`, `l5`, `l15` |
| `mem` | `total_mb`, `available_mb`, `used_pct` |
| `swap` | `total_mb`, `used_mb`, `in_ps`, `out_ps` (pages swapped in / out per second) |
| `disks[]` | `mount`, `fs`, `total_gb`, `free_gb`, `used_pct`, `inode_used_pct`, `growth_mb_h`, `days_to_full` |
| `temps[]` | `name`, `c` (omitted when there are no sensors) |
| `net` | `rx_bps`, `tx_bps`: bit/s received (download) and sent (upload) since the previous sample, summed over the included interfaces (integers). Omitted on the first sample, and on a sample where an interface appeared, went away or its counters went backwards. Only `/proc/net/dev` byte counters are read: no addresses, connections or interface names |

## `events[]`

| Field | Description |
| --- | --- |
| `id` | Event ID; the same ID appearing again means an update (count increased, etc.) |
| `ts`, `last_ts` | First / most recent occurrence time |
| `type`, `severity` | Type and severity (P0–P3) |
| `count`, `key` | Number of occurrences within the debounce window; merge key (unit name, process name, source network, etc.) |
| `data` | Type-specific fields, see the table below |
| `snapshot` | Incident context for severe events: the last 10 minutes of metrics, and the top 5 processes by memory and by CPU (`pid`, `comm`, redacted `cmdline`, `uid`, `rss_mb`, `cpu_pct`, owning `unit`) |

| type | data |
| --- | --- |
| `service_failed` | `unit`, `result`, `exit_code`, `signal`, `restarting`, `n_restarts`, `memory_peak_mb`, `log_tail[]` (the service's most recent log lines) |
| `service_start_failed` | `unit`, `job_result`, `log_tail[]` |
| `oom_kill` | `victim`, `pid`, `total_vm_mb`, `anon_rss_mb`, `file_rss_mb`, `shmem_rss_mb`, `oom_score_adj`, `scope`, `constraint`, `memcg` |
| `proc_segfault` | `comm`, `pid`, `module` |
| `disk_error`, `fs_readonly` | `device`, `message` |
| `hung_task` | `comm`, `pid`, `blocked_seconds` |
| `ssh_bruteforce`, `ssh_spray` | `source` (redacted network), `fail_count`, `user_count`, `top_users[]`, `window_seconds` |
| `ssh_breach` | `source`, `user`, `method`, `prior_failures` |
| `ssh_root_password_login` | `source` |
| `sudo_sensitive` | `by_user`, `as_user`, `command` (redacted), `pwd` |
| `sudo_auth_fail` | `user`, `attempts` |
| `user_created` | `name`, `uid` |
| `su_root` | `by_user` |
| `proc_fileless`, `proc_deleted_exe`, `proc_stale_binary`, `proc_tmp_exec` | `pid`, `comm`, `exe`, `cmdline`, `uid`, `ppid_comm` |
| `proc_reverse_shell` | Same as above, plus `remote` (redacted) |
| `swap_thrashing`, `mem_pressure` | `in_ps`, `available_mb`, `swap_used_mb` |

## Example

```json
{
  "v": 1, "seq": 10423, "sent_at": 1790000000,
  "agent_version": "1.0.0", "machine_fp": "9c1e4b7a0d2f6e38",
  "metrics": [{
    "ts": 1789999985,
    "cpu": {"total_pct": 12.5, "iowait_pct": 0.4, "steal_pct": 0},
    "load": {"l1": 0.31, "l5": 0.27, "l15": 0.22},
    "mem": {"total_mb": 3931, "available_mb": 2210, "used_pct": 43.8},
    "disks": [{"mount": "/", "fs": "ext4", "total_gb": 78.7, "free_gb": 51.2, "used_pct": 34.9}]
  }],
  "events": [{
    "id": "evt_01J…", "ts": 1789999990, "type": "service_failed", "severity": "P1", "count": 1, "key": "app.service",
    "data": {"unit": "app.service", "result": "core-dump", "signal": "SEGV", "restarting": true, "n_restarts": 3,
             "log_tail": ["connecting to postgres://[REDACTED:cred]@10.0.0.5/app", "fatal: segfault at 0"]}
  }],
  "redactions": {"url_cred": 1}
}
```

## How the server treats this data

- After decompression and before any processing, the ingest gateway computes sha256 over the raw bytes and writes it, together with the original content, to an audit table (kept for 7 days). The [console's transparency audit page](../README.md#verify-it-yourself) shows exactly this original content.
- Access logs record no request bodies, no IPs and no tokens; the source IP is written only to the audit table. When relayed through the [Worker](relay.md), the server sees only Cloudflare's address.
- Deleting a server in the console immediately revokes its token, and a background job hard-deletes all of its data.

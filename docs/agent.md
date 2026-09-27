# xnux-agent

English | [简体中文](agent.zh-CN.md)

Implemented: resource metric collection, the redaction barrier, batched reporting with offline buffering, dry-run and the mirror file (stage 1); incident-context event capture: service crashes, kernel events, security logs, suspicious-process scans, incident-context snapshots (stage 4); network throughput (stage 9); local black box: standalone mode, local storage, the `xnux` CLI, connect / disconnect hot switching (stage 11; user guide in [standalone.md](standalone.md)).

## Commands

| Command | Purpose |
| --- | --- |
| `xnux-agent run` | Run normally (default) |
| `--dry-run` | Collect and redact as usual and print the payload to stdout; opens no network connections and writes no spool or state |
| `--once` | Collect one round (about 1 second), send, and exit; can be combined with `--dry-run` |
| `--print-config` | Print the effective config; the token shows only its last 4 characters |
| `--check` | Self-test each collector and endpoint connectivity |
| `--state-dir` / `--log-dir` | Override the defaults `/var/lib/xnux` and `/var/log/xnux` |
| `--socket` | CLI socket, default `/run/xnux/agent.sock` (the `XNUX_SOCKET` environment variable also works) |
| `cli …` | Same as `xnux …` (when invoked under the name `xnux`, the binary acts as the CLI) |
| `version` | Version, commit, Go version |

In a terminal, `--dry-run` output is colorized: keys in cyan, values in yellow, redaction markers in white on red. When piped, it prints plain JSON and writes the summary line to stderr, so `| jq` works.

## Transparency

| To confirm | How |
| --- | --- |
| What will be sent | `xnux-agent --dry-run --once` |
| What was just sent | `cat /var/log/xnux/last_outgoing_payload.json`; `mirror_history: N` keeps the last N payloads in `/var/log/xnux/outgoing/` |
| Whether the server received the same thing | `last_outgoing_payload.sha256` is the sha256 of the raw (pre-compression) bytes; compare it with the hash shown on the console's transparency audit page |
| Whether the binary matches the source | Reproducible build; see [install.md](install.md#verify-the-binary-matches-the-source) |

## Redaction rules

The full user-facing description is in [redaction.md](redaction.md); for installation and least privilege see [install.md](install.md) and [least-privilege.md](least-privilege.md). What follows are the differences between the implementation and the spec.

Rules are applied in order to every string in the payload (including event data, log lines and process command lines). Redaction markers are self-describing; the console's transparency audit page highlights them using `proto/redaction_markers.json`. Built-in rules cannot be disabled through config; `sanitize.extra_patterns` can only add more.

The implementation follows spec A6.3, strengthened in a few places on the principle of "better to over-redact than to leak" (each has a matching case in the golden corpus):

| Rule | Spec | Implementation |
| --- | --- | --- |
| `private_key` | `PRIVATE KEY-----` | Also covers PGP's `PRIVATE KEY BLOCK-----` |
| `kv_secret` | Bare words such as `\bpassword=…` | Also covers prefixed names (`MYSQL_ROOT_PASSWORD=`, `spring.datasource.password=`), JSON keys (`"db_password": "x"`), and `password …: value` (the MySQL temporary password log line) |
| `cli_secret` `-pXXXX` | Command-line fields only | All strings (covers commands quoted in logs, such as sudo's `COMMAND=`) |
| `ipv6` | Public unless in the private-network list | Masks only 2000::/3 (the range holding all public unicast addresses) and skips candidates directly adjacent to a word, so `std::string` and `ab::cd` are not hit |
| Already-redacted values | — | kv / cli rules do not rewrite a value that is already a redaction marker; `token [REDACTED:api_key]` keeps its specific type and is not counted twice |

The spec's `password\s+value` form turns `Failed password for root` into `Failed password [REDACTED:secret] root`; this is the spec's behavior as written.

## Event capture (stage 4)

```
systemd (D-Bus) ─┐
/dev/kmsg ───────┤
auth.log/journal ┼─► rule engine (clean → security state machine → debounce) ─► snapshot ─► batch ─► redaction barrier ─► send
/proc scan ──────┤
metric samples ──┘   (memory rules)
```

| Watcher | Source | Events |
| --- | --- | --- |
| systemd | system bus `Subscribe` + `PropertiesChanged` / `JobRemoved` | `service_failed` (including `auto-restart`), `service_start_failed`, `service_recovered`; with the exit code or signal name, `NRestarts`, `MemoryPeak`, and the last 50 lines of `journalctl -u` |
| kmsg | `/dev/kmsg`, read from the end | `oom_kill` (global / memcg, merging the `oom-kill:constraint` line), `proc_segfault`, `disk_error`, `fs_readonly`, `hung_task` |
| authlog | `/var/log/auth.log` → `/var/log/secure` → `journalctl -f` | Raw records are not reported; they only feed the security state machine: `ssh_bruteforce`, `ssh_spray`, `ssh_breach`, `ssh_root_password_login`, `sudo_sensitive`, `sudo_auth_fail`, `user_created`, `su_root` |
| procscan | Scans `/proc` every 300 seconds + a random 0–30 second offset | `proc_reverse_shell`, `proc_fileless`, `proc_deleted_exe`, `proc_stale_binary`, `proc_tmp_exec` |
| metrics | Every sample | `swap_thrashing`, `mem_pressure` |

- Unavailable collectors (no systemd, unreadable `/dev/kmsg`, no security log source) are disabled at startup and do not appear in `capabilities`; `--check` explains each one.
- If a watcher fails, only that watcher is restarted (exponential backoff from 1 second up to 5 minutes); restarts are counted in `diag.collector_errors`.
- The security state machine is keyed by full source IP and lives only in memory (LRU of 10,000 entries, expiring after 30 minutes of inactivity); it is never written to disk. When reported, IPs pass through the redaction barrier and only the subnet remains (`8.8.4.x`).
- Repeats with the same fingerprint (type + primary key) within 60 seconds only increment `count`; when the window ends, one update is sent (same event id); if repeats continue, they keep being merged. P0 is not debounced. After brute force / password spraying triggers, a 10-minute quiet period follows during which only counts are kept; at its end, if the activity is still ongoing, one update is sent.
- P0 / P1, `oom_kill`, `service_failed` and `mem_pressure` get an incident-context snapshot the first time they occur: metrics for the last 10 minutes (one point per sample interval) and the top 5 processes by RSS and by CPU (two reads 500 ms apart), each with its cleaned and redacted command line and its systemd unit. A snapshot takes at most 2 seconds; if it fails, the event is still sent.
- When an event arrives, the agent waits 1 second to collect events in the same batch, then sends them (together with pending metrics); P0 is sent immediately.
- There are only two external commands: `journalctl -u <unit> -n 50` when an event occurs (3-second timeout), and a long-running `journalctl -f -o json` when there is no auth.log / secure.
- Security log file mode: watches the directory for create / rename / delete and the file itself for modifications; after a logrotate rename, keeps reading the old file until the writer starts writing the new one; on copytruncate, rereads from the start. The position (device, inode, offset of the end of the last complete line) is written to state.json every 10 seconds and on exit, and reading resumes after a restart; if the file has been rotated in the meantime, the remainder of `path.1` is read first.

### Event severity

Severities for security and process events follow spec A4.2 / A3.4. Where the spec does not specify an event, the agent defaults to:

| Event | Severity |
| --- | --- |
| `service_failed`, `service_start_failed`, `oom_kill`, `disk_error`, `fs_readonly` | P1 |
| `proc_segfault`, `hung_task`, `swap_thrashing`, `mem_pressure` | P2 |
| `service_recovered` | P3 |

### Differences from the spec

| Item | Spec | Implementation | Reason |
| --- | --- | --- | --- |
| kmsg timestamp | `btime + ts_usec` | Current time minus the record's age (by CLOCK_MONOTONIC) | On hosts that have been suspended or live-migrated, the btime formula can be off by hours (measured in development: off by 4 hours); the agent only reads new records, so converting by age is accurate |
| `ssh_invalid_user` | Counted as a failure | Counted only toward usernames (password-spraying rule), not toward the failure count | sshd immediately also logs `Failed password for invalid user …`; counting both would double the failure count |
| sudo authentication failure | Each matching line counts once | Counts by the number in the summary line (`3 incorrect password attempts` counts as 3); if the same line carries `COMMAND=`, the sensitive-command check still runs | sudo logs only one summary line per invocation; the per-attempt pam_unix lines are not counted again |
| Disk device name | `dev (\w+)` / `\((\w+)\)` | Also recognizes ext4's `(device sda1)` | Otherwise ext4 errors get no device name |
| Debounce window | Send an update when the 60-second window closes | On close, if there were repeats, send an update and start another window (same id); ends only after a full quiet window | Keeps a continuous crash loop as one event instead of a new event every minute |
| First process scan | 300 seconds + offset | First scan 0–30 seconds after startup | Problems already present at startup don't have to wait 5 minutes |
| `restarting` on service crash | true in the `auto-restart` substate | Same; on systemd 255, a `Restart=always` service that crashes enters `failed` first and then restarts, in which case `restarting: false` is reported | Follows the state sequence systemd actually emits |

### Measured in development

| Acceptance item | Method | Result |
| --- | --- | --- |
| F4-1 `kill -SEGV` produces an event within 1 second with the correct signal | systemd as PID 1 in a container, real service | `service_failed` within the same second, `signal: SIGSEGV`, with the journal tail; also tested SIGABRT, exit 203, and `service_recovered` after 60 seconds |
| F4-2 OOM process name and memory figures are accurate | python allocating memory in a cgroup with a 64 MB memory limit | `oom_kill` victim `python3`, pid, `anon_rss_mb: 67`, `scope: memcg`, `constraint: CONSTRAINT_MEMCG` match the kernel |
| F4-3 No missed or duplicated lines across logrotate | Unit tests: rename + create (old file still being written), copytruncate, restart after a rotation during downtime | Every line exactly once; on a real host, a breach whose failures and success fell on either side of a rotation was correctly rated P0 |
| F4-4 Sample log graded correctly | Replay of `internal/rules/testdata/auth.log` | All 9 event types and severities correct; an update is sent when the brute-force quiet period ends |
| F4-5 `bash -i >& /dev/tcp/…` is detected | Real process | `proc_reverse_shell` P0, `remote: 127.0.0.1:4445`; one scan of 1099 processes takes 10–26 ms |
| Resources | `scripts/agent-resource-check.sh`, all collectors enabled | VmRSS 13.5 MB, average CPU 0.012% |

## Protocol details

- `machine_fp` = the first 16 characters of sha256(machine-id + token). The spec says machine-id + server_id, but the agent doesn't know server_id; the token serves the same salting purpose.
- Spool file names are `<seq, 20 digits>[.<part>][.e].json.gz`; `.e` marks files that contain events (deleted last on eviction).
- A 413 splits only payloads that have not been split before (into part 1 and 2); the batching stage already pre-splits at 512 KB compressed / 4 MB raw, so this normally doesn't happen.
- A new or corrupted state.json starts numbering from the current Unix time in milliseconds, so seq after a reinstall is higher than anything the server has recorded (the server deduplicates by max seq).
- state.json is not rewritten when its content hasn't changed.

## Local black box (stage 11)

- Process model: in `loop`, `app` opens local storage (`internal/localstore`: event JSONL + metric ring files) and the socket server (`internal/ipc`); the sender is created by `connect()` only when there is a token. In standalone mode, the batcher's output is kept only as the latest copy (`xnux payload --next`); no spool is created and no requests are sent.
- Hot reload: `xnux connect / disconnect` rewrites `/etc/xnux/agent.yaml` (keeping 0600, replacing only top-level keys) and then sends `reload`. The daemon rereads its config; when the token, endpoint, proxy or TLS settings change, it tears down the old sender, builds a new one reusing the spool, and immediately flushes a registration payload. All other collection continues uninterrupted.
- Socket: 0660, group `xnux` (root-only if the group doesn't exist); users outside the group get EACCES, and the CLI suggests joining the `xnux` group. Requests and responses are one line of JSON each; a request line over 64 KB is disconnected, at most 8 connections are allowed at once, and idle connections are dropped after 5 minutes.
- The local health score (`internal/localhealth`) uses the same `xnux-shared/health` algorithm as the server: the inputs are the per-minute records from the last hour and events from the last 24 hours (events within 24 hours are treated as unrecovered); with less than 50 minutes of data in the last hour it shows "collecting".
- CLI resources: `xnux top` makes one IPC call every 2 seconds and uses about 0.15% CPU itself.

Differences from the spec:

- The systemd unit does not add `/run/xnux` to `ReadWritePaths`: `RuntimeDirectory=xnux` is already writable under `ProtectSystem=strict`, and the directory is created only just before startup, so listing it in `ReadWritePaths` would actually make startup fail if the directory is missing.
- The spec requires the install script to "ask whether to add the current sudo user"; it asks only when run interactively from a terminal (`/dev/tty` is readable) and `SUDO_USER` is set, so `curl | sudo sh` does not hang in CI.

## Network throughput (stage 9)

- Source: `/proc/net/dev`, read on the metric ticker through a file handle kept open; no external commands. The rate is the byte-counter difference × 8 ÷ the time between the two reads (the tick's exact time, not rounded to the second).
- Interfaces: all except `lo`, `docker*`, `veth*`, `br-*`, `virbr*`, `cni*`, `flannel*`, `cali*`, summed. `network.include` (glob patterns) replaces that choice with the interfaces it names; `network.exclude` always applies.
- The first sample and any sample where an interface appeared or went away, or a counter went backwards (wrap, interface recreated, reboot), only record the baseline and omit `net`, so a restarted interface never shows a spike.
- `xnux top` asks the daemon for the counters on every frame and shows the rate between two frames 2 s apart (the first frame shows the last sample's rate). The metric ring keeps the average per minute for `xnux history`; a ring written by an older version is converted on start, keeping its history.
- Cost: about 8 µs more per sample and one 16-byte allocation (the `net` object); the counter buffers are reused.

| Check | Method | Result |
| --- | --- | --- |
| F9-4 accuracy < 5% | A generator sending exactly 10,000,000 B/s over TCP for 40 s (80.00 Mbps), `network.include: [lo]` | `xnux top` 79.7–81.4 Mbps per 2-s frame, sampled points 80.07–80.11 Mbps |
| No spike after an interface restarts | Unit test: counters reset between samples | That sample omits `net`; the next is normal |

## Resource benchmark (F1-9)

```sh
DURATION=120 scripts/agent-resource-check.sh
```

Runs the agent against a local fake ingest and samples it. Measured in development (4-core VM): at stage 1, VmRSS about 12.4 MB; at stage 4 with all event collectors enabled, about 13.5 MB with 0.012% average CPU; a single sample takes about 15 µs with 0 allocations. CI runs it for 180 seconds every time. At stage 7, it was sampled for 60 seconds in containers of each of 6 distros: VmRSS 11.7–13.7 MB. Since stage 11, CI runs it in both connected and standalone modes (in standalone mode it also calls `xnux status` once a minute); measured in development: connected 13.7 MB / 0.029%, standalone 12.9 MB / 0.035%. On kernels with transparent huge pages set to `always` (as on GitHub's runners), the Go runtime backs the heap with 2 MB huge pages, adding 3–4 MB of resident memory; when the daemon detects this, it re-executes itself once with `GODEBUG=disablethp=1`, which measured back at 13.7 / 12.2 MB.

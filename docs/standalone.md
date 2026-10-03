# Black box: useful without connecting to Xnux

English | [简体中文](standalone.zh-CN.md)

Installed without an agent key, the agent runs in **standalone mode**: it continuously records metrics and the incident context of crashes, OOMs and intrusions on the machine, and after something goes wrong you inspect it with the `xnux` command. It makes no network connections, requires no sign-up, and is free.

![xnux top](img/xnux-top.png)

## Installation

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/install.sh | sudo sh
```

Same binary and same install script as connected mode, just without `--token`. The script:

- installs `/usr/local/bin/xnux-agent` and creates the symlink `/usr/local/bin/xnux` (the invoked name decides between daemon and command line);
- creates the `xnux` group and asks whether to add the current sudo user to it (once added, you can use `xnux` without sudo, effective from your next login). For non-interactive installs use `--add-user alice` or `--no-prompt`.

## Commands

| Command | Purpose |
| --- | --- |
| `xnux top` | Live terminal dashboard: CPU, load, memory, swap, disks (with time until full), temperatures, network download / upload rate (from counters 2 s apart), top 5 processes, last 5 events, health score; refreshes every 2 seconds, `--once` prints a single frame |
| `xnux events [--type T,…] [--since 24h] [--severity P0,…]` | Events recorded on this machine (kept for 30 days) |
| `xnux event ID` | Full incident context for one event: exit code, signal, log tail, process snapshot, charts of the 10 minutes before the event |
| `xnux history [--metric cpu,mem,load,disk,net] [--hours 24]` | Terminal line charts of the last 24 hours of metrics (`net`: average download / upload rate per minute) |
| `xnux status` | Collectors, mode (standalone / connected), storage usage, breakdown of health score deductions |
| `xnux payload [--last\|--next]` | What was last reported / what will be reported next |
| `xnux connect --token xat_… [--endpoint URL]` | Switch to connected mode (requires root) |
| `xnux disconnect` | Switch back to standalone mode and delete the agent key (requires root) |

All commands support `--json`. When the terminal is narrower than 80 columns, `xnux top` automatically uses a compact layout; when `LANG` contains `zh`, health score explanations are in Chinese.

![xnux history and xnux events](img/xnux-history.png)

## Local storage

| Path | Contents |
| --- | --- |
| `/var/lib/xnux/events/YYYYMMDD.jsonl` | Events, append-only, fsync after each record; a file over 10 MB is rotated (`YYYYMMDD.1.jsonl`…), kept for 30 days |
| `/var/lib/xnux/metrics.ring` | Ring file of 1440 slots × 72 bytes, one record per minute: averages; disks and temperatures take the worst value of that minute |
| `/run/xnux/agent.sock` | Unix socket between the command line and the daemon, 0660, group `xnux`; newline-delimited JSON |

What is stored locally is **raw** data (it never leaves the machine), and all files are 0600. Only after switching to connected mode does data pass through the redaction barrier before being sent; see [redaction.md](redaction.md). The total cap is 350 MB (when events exceed 340 MB the oldest files are deleted).

Power-loss safety: each event is fsynced; a half-written last line gets a newline appended before the next write and is skipped on read; each metrics record carries a CRC, and a corrupted minute is skipped on read. At most the last record is lost.

## Relationship to Xnux

| Local (free, open source) | Xnux SaaS |
| --- | --- |
| Single server | Many servers in one place |
| Metrics for 24 hours (1-minute resolution), events for 30 days | Long-term history and charts |
| Inspect manually, **no alerts of any kind** | Alert notifications (free tier includes 2 servers) |
| Raw incident context data | AI analysis, app fixes, uptime checks, status pages, teams |

When you want alerts:

```sh
sudo xnux connect --token xat_…     # the agent key from "Add server" in the console
```

`connect` writes the configuration and then notifies the daemon over the socket to reload **without restarting**: the reporting channel is set up on the spot, the first batch of data arrives within seconds, and local recording is not interrupted. `xnux disconnect` does the reverse: it deletes the agent key, stops reporting, and keeps recording locally.

## Verify that it really stays offline

```sh
xnux status                  # mode: standalone
sudo ss -tnp | grep xnux     # no connections at all
```

In standalone mode the reporting module is never initialized; the daemon listens only on that Unix socket and on no network port.

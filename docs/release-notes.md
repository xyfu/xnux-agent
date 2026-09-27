## Black box: works without Xnux

Installed without a token, the agent is a black box for the machine: it keeps recording metrics (24 hours at 1-minute resolution) and crash, OOM and intrusion context (30 days), and the `xnux` command shows it after the fact. **No network connections, no alerts, free.**

![xnux top](https://raw.githubusercontent.com/xyfu/xnux-agent/@VERSION@/docs/img/xnux-top.png)

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/download/@VERSION@/install.sh | sudo sh
```

| Command | What it does |
| --- | --- |
| `xnux top` | Live dashboard: CPU, load, memory, disks, temperature, top processes, recent events, health score |
| `xnux events` / `xnux event ID` | Event list / full context (exit code, log tail, process snapshot, the 10 minutes before) |
| `xnux history` | Metric charts for the last 24 hours |
| `xnux status` | Collectors, mode, health score deductions |
| `xnux payload [--last\|--next]` | What was just sent / will be sent next |
| `xnux connect --token …` / `xnux disconnect` | Switch to reporting / standalone mode without a restart |

![xnux history](https://raw.githubusercontent.com/xyfu/xnux-agent/@VERSION@/docs/img/xnux-history.png)

See [docs/standalone.md](https://github.com/xyfu/xnux-agent/blob/@VERSION@/docs/standalone.md) ([简体中文](https://github.com/xyfu/xnux-agent/blob/@VERSION@/docs/standalone.zh-CN.md)).

## Verification

Every file comes with a cosign signature (`.sig` / `.pem`). Binaries build reproducibly: run `make agent VERSION=@VERSION@ COMMIT=<commit>` and compare with `SHA256SUMS`. Resource benchmark (both connected and standalone mode): resident memory < 15 MB, idle CPU < 0.05%.

# 上报字段说明

[English](payload.md) | 简体中文

探针只有一个出站请求：`POST {endpoint}/v1/ingest`。服务端的响应里只有确认序号、服务端时间和可选提示（`agent_outdated`、`clock_skew`），没有任何探针会执行的指令或配置——探针不接收远程命令。

机器可读的定义：[proto/ingest.v1.schema.json](https://github.com/xyfu/xnux-shared/blob/main/proto/ingest.v1.schema.json)（JSON Schema，在 [xnux-shared](https://github.com/xyfu/xnux-shared) 仓库）。想看自己机器上的真实内容：`xnux-agent --dry-run --once`，或 `/var/log/xnux/last_outgoing_payload.json`。

## 请求

```http
POST /v1/ingest HTTP/1.1
Content-Type: application/json
Content-Encoding: gzip
Authorization: Bearer xat_…
User-Agent: xnux-agent/1.0.0 (linux; amd64)
X-Xnux-Seq: 10423
X-Xnux-Schema: 1
```

TLS ≥ 1.2 且校验证书（没有“跳过校验”选项，私有 CA 用 `tls.ca_file`）；压缩后 ≤ 512 KB、解压后 ≤ 4 MB。默认每 15 秒采样、每 60 秒上报一次；有事件时立即上报。发送前每个字符串都经过[脱敏屏障](redaction.zh-CN.md)。

## 顶层

| 字段 | 说明 |
| --- | --- |
| `v` | 协议版本，固定 1 |
| `seq` | 单调递增序号，服务端据此去重（重发安全） |
| `part` | 过大被拆分时的分片号 |
| `sent_at` | 探针本地时间（Unix 秒） |
| `agent_version` | 探针版本 |
| `machine_fp` | sha256(machine-id + token) 前 16 位，用于发现“同一个接入密钥被复制到多台机器” |
| `host` | 主机信息：启动时、每 6 小时、变化时携带 |
| `metrics[]` | 资源指标，按时间升序 |
| `events[]` | 现场事件 |
| `diag` | 探针自诊断：`rss_mb`、`spool_mb`、`kmsg_lost`、`dropped_metrics`、`collector_errors` |
| `security_summary` | 每小时一次，无论[风险扫描](risk-scan.zh-CN.md)结果如何：过去一小时 SSH 登录失败的汇总——`start`、`end`、`attempts`、`root_attempts`（其中针对 root 用户的次数）、`sources`（本小时来源个数，只计数）、`sources_24h`（截至 `end` 的 24 小时来源去重个数，只计数）与 `top_users[]`（`user`、`count`，最多 5 个）。不含认证方式和地址 |
| `services_failed` | 当前处于失败或崩溃后自动重启中的 `.service` 单元名：启动时、D-Bus 重连时、清单变化时和每小时一次上报；`[]` 表示没有。服务端据此结束单元已不在清单中的服务事件。未启用 systemd 采集器时省略 |
| `redactions` | 本条载荷里各脱敏规则的命中次数，如 `{"ipv4": 2}` |

## `host`

| 字段 | 来源 |
| --- | --- |
| `hostname` | 主机名；`hide_hostname: true` 时为 `host` |
| `os` | `/etc/os-release` 的 `PRETTY_NAME` |
| `kernel`、`arch` | `uname` |
| `cores`、`uptime`、`virt` | CPU 数、开机秒数、虚拟化类型 |
| `capabilities` | 实际开启的采集器：`metrics`、`temps`、`systemd`、`kmsg`、`authlog`、`procscan` |

不采集：IP 地址、MAC、网卡列表、用户列表、已安装软件、文件内容、环境变量。

## `metrics[]`

| 字段 | 内容 |
| --- | --- |
| `ts` | 采样时间 |
| `cpu` | `total_pct`、`iowait_pct`、`steal_pct` |
| `load` | `l1`、`l5`、`l15` |
| `mem` | `total_mb`、`available_mb`、`used_pct` |
| `swap` | `total_mb`、`used_mb`、`in_ps`、`out_ps`（每秒换入 / 换出页） |
| `disks[]` | `mount`、`fs`、`total_gb`、`free_gb`、`used_pct`、`inode_used_pct`、`growth_mb_h`、`days_to_full` |
| `temps[]` | `name`、`c`（没有传感器时省略） |
| `net` | `rx_bps`、`tx_bps`：与上一次采样相比，纳入网卡合计的接收（下行）、发送（上行）速率，单位 bit/s，整数。首次采样，以及有网卡新增、消失或计数回退的那一次采样省略。只读 `/proc/net/dev` 的字节计数：不采集地址、连接，也不上报网卡名 |

## `events[]`

| 字段 | 说明 |
| --- | --- |
| `id` | 事件 ID；同一 ID 再次出现表示更新（计数增加等） |
| `ts`、`last_ts` | 首次 / 最近发生时间 |
| `type`、`severity` | 类型与级别（P0–P3） |
| `count`、`key` | 防抖期内的次数；合并键（unit 名、进程名、来源网段等） |
| `data` | 按类型的字段，见下表 |
| `snapshot` | 严重事件的现场：最近 10 分钟指标序列，按内存和 CPU 排序的前 5 个进程（`pid`、`comm`、脱敏后的 `cmdline`、`uid`、`rss_mb`、`cpu_pct`、所属 `unit`） |

| type | data |
| --- | --- |
| `service_failed` | `unit`、`result`、`exit_code`、`signal`、`restarting`、`n_restarts`、`memory_peak_mb`、`log_tail[]`（该服务最近的日志行） |
| `service_start_failed` | `unit`、`job_result`、`log_tail[]` |
| `oom_kill` | `victim`、`pid`、`total_vm_mb`、`anon_rss_mb`、`file_rss_mb`、`shmem_rss_mb`、`oom_score_adj`、`scope`、`constraint`、`memcg` |
| `proc_segfault` | `comm`、`pid`、`module` |
| `disk_error`、`fs_readonly` | `device`、`message` |
| `hung_task` | `comm`、`pid`、`blocked_seconds` |
| `ssh_bruteforce`、`ssh_spray` | 仅当[风险扫描](risk-scan.zh-CN.md)发现 SSH 允许密码登录时上报；按服务器合并为一条（`key` 为类型）。`source`（最近的来源，已脱敏网段）、`fail_count`、`user_count`、`top_users[]`、`window_seconds`、`source_count`、`root_password`（root 是否允许密码登录）；允许时为 P1 并带 `root_attempts` |
| `ssh_breach` | `source`、`user`、`method`、`prior_failures` |
| `ssh_root_password_login` | `source` |
| `sudo_sensitive` | `by_user`、`as_user`、`command`（已脱敏）、`pwd` |
| `sudo_auth_fail` | `user`、`attempts` |
| `user_created` | `name`、`uid` |
| `su_root` | `by_user` |
| `proc_fileless`、`proc_deleted_exe`、`proc_stale_binary`、`proc_tmp_exec` | `pid`、`comm`、`exe`、`cmdline`、`uid`、`ppid_comm` |
| `proc_reverse_shell` | 同上，加 `remote`（已脱敏）；`key` 与其他进程事件一样是可执行文件路径 |
| `swap_thrashing`、`mem_pressure` | `in_ps`、`available_mb`、`swap_used_mb` |
| `db_public_access` | 仅当数据库端口监听在公网时：`port`、`service`、`bind_scope`（`all_interfaces` 所有网卡或 `public_address` 公网地址；从不上报地址本身）、`connections`、`sources[]`（已脱敏网段）；每端口每小时最多 1 条 |
| `docker_api_access` | 仅当 Docker API 以未加 TLS 的 TCP 对外时：`port`、`tls`（恒为 `false`）、`bind_scope`、`connections`、`sources[]`；每端口每小时最多 1 条 |

## 示例

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

## 服务端怎么对待这些数据

- 接入网关解压后、任何处理之前，对原始字节算 sha256，连同原文写入审计表（保留 7 天），[审计台](../README.zh-CN.md#透明度验证三步)展示的就是这份原文。
- 访问日志不记请求体、不记 IP、不记接入密钥；来源 IP 只写审计表。经 [Worker](relay.zh-CN.md) 转发时服务端只看到 Cloudflare 的地址。
- 在控制台删除服务器会立即作废接入密钥，并由后台任务硬删除它的全部数据。

# xnux-agent 探针

[English](agent.md) | 简体中文

已实现：资源指标采集、脱敏屏障、批量上报与断网缓冲、dry-run 与镜像文件（阶段 1）；现场事件捕获：服务崩溃、内核事件、安全日志、可疑进程巡检、现场快照（阶段 4）；本地黑匣子：独立模式、本地存储、`xnux` 命令行、connect / disconnect 热切换（阶段 11，用户说明见 [standalone.zh-CN.md](standalone.zh-CN.md)）。

## 命令

| 命令 | 作用 |
| --- | --- |
| `xnux-agent run` | 正常运行（默认） |
| `--dry-run` | 正常采集与脱敏，载荷打印到 stdout，不建立任何网络连接、不写 spool 和 state |
| `--once` | 采集一轮（约 1 秒）后发送并退出；可与 `--dry-run` 连用 |
| `--print-config` | 打印生效配置，token 只显示末 4 位 |
| `--check` | 自检各采集器与 endpoint 连通性 |
| `--state-dir` / `--log-dir` | 覆盖默认的 `/var/lib/xnux`、`/var/log/xnux` |
| `--socket` | 命令行 Socket，默认 `/run/xnux/agent.sock`（也可用环境变量 `XNUX_SOCKET`） |
| `cli …` | 等同于 `xnux …`（以 `xnux` 名字调用时即为命令行） |
| `version` | 版本、commit、Go 版本 |

`--dry-run` 在终端里着色：键名青色、数值黄色、脱敏替换符红底白字；管道输出时为纯 JSON，摘要行写到 stderr，便于 `| jq`。

## 透明度

| 想确认 | 方法 |
| --- | --- |
| 会发什么 | `xnux-agent --dry-run --once` |
| 刚才发了什么 | `cat /var/log/xnux/last_outgoing_payload.json`；`mirror_history: N` 保留最近 N 条到 `/var/log/xnux/outgoing/` |
| 服务端收到的是否一致 | `last_outgoing_payload.sha256` 是原始（压缩前）字节的 sha256，与审计台显示的哈希对比 |
| 二进制是否对应源码 | 可复现构建，见 [install.zh-CN.md](install.zh-CN.md#校验二进制与源码一致) |

## 脱敏规则

面向用户的完整说明见 [redaction.zh-CN.md](redaction.zh-CN.md)；安装与最小权限见 [install.zh-CN.md](install.zh-CN.md)、[least-privilege.zh-CN.md](least-privilege.zh-CN.md)。以下是实现与规格的差异。

规则按顺序作用于载荷中的每一个字符串（含事件数据、日志行、进程命令行），替换符是自标记的，审计台用 `proto/redaction_markers.json` 高亮。内置规则不能通过配置关闭，`sanitize.extra_patterns` 只能追加。

实现以规格 A6.3 为准，以下几处按“宁可误伤不可漏掉”做了加强（黄金语料中都有对应用例）：

| 规则 | 规格 | 实现 |
| --- | --- | --- |
| `private_key` | `PRIVATE KEY-----` | 另外覆盖 PGP 的 `PRIVATE KEY BLOCK-----` |
| `kv_secret` | `\bpassword=…` 等裸词 | 另外覆盖带前缀的名字（`MYSQL_ROOT_PASSWORD=`、`spring.datasource.password=`）、JSON 键（`"db_password": "x"`）、`password …: 值`（MySQL 临时密码日志） |
| `cli_secret` `-pXXXX` | 仅命令行字段 | 所有字符串（覆盖日志里引用的命令，如 sudo 的 `COMMAND=`） |
| `ipv6` | 不在私网列表即公网 | 只遮蔽 2000::/3（全部公网单播地址所在段），并排除紧贴单词的候选，避免 `std::string`、`ab::cd` 误伤 |
| 已脱敏的值 | — | kv / cli 规则遇到已是替换符的值不再改写，`token [REDACTED:api_key]` 保留具体类型且不重复计数 |

规格中的 `password\s+值` 形式会让 `Failed password for root` 变成 `Failed password [REDACTED:secret] root`，这是规格原样行为。

## 事件捕获（阶段 4）

```
systemd (D-Bus) ─┐
/dev/kmsg ───────┤
auth.log/journal ┼─► 规则引擎（清洗 → 安全状态机 → 防抖）─► 快照 ─► 批处理 ─► 脱敏屏障 ─► 发送
/proc 巡检 ──────┤
指标采样 ────────┘   （内存规则）
```

| 监听器 | 来源 | 事件 |
| --- | --- | --- |
| systemd | system bus `Subscribe` + `PropertiesChanged` / `JobRemoved` | `service_failed`（含 `auto-restart`）、`service_start_failed`、`service_recovered`；附退出码或信号名、`NRestarts`、`MemoryPeak`、`journalctl -u` 最后 50 行 |
| kmsg | `/dev/kmsg`，从末尾读 | `oom_kill`（全局 / memcg，合并 `oom-kill:constraint` 行）、`proc_segfault`、`disk_error`、`fs_readonly`、`hung_task` |
| authlog | `/var/log/auth.log` → `/var/log/secure` → `journalctl -f` | 原始记录不上报，只喂安全状态机：`ssh_bruteforce`、`ssh_spray`、`ssh_breach`、`ssh_root_password_login`、`sudo_sensitive`、`sudo_auth_fail`、`user_created`、`su_root` |
| procscan | 每 300 秒 + 0–30 秒随机偏移扫描 `/proc` | `proc_reverse_shell`、`proc_fileless`、`proc_deleted_exe`、`proc_stale_binary`、`proc_tmp_exec` |
| 指标 | 每次采样 | `swap_thrashing`、`mem_pressure` |

- 不可用的采集器（非 systemd、`/dev/kmsg` 不可读、无安全日志来源）启动时关闭，不出现在 `capabilities` 里；`--check` 逐项说明。
- 任一监听器出错只重启它自己（1 秒起指数退避到 5 分钟），次数计入 `diag.collector_errors`。
- 安全状态机以完整来源 IP 为键，只在内存里（LRU 1 万项，30 分钟无活动过期），不落盘；上报时 IP 经脱敏屏障只剩网段（`8.8.4.x`）。
- 同指纹（类型 + 主键）60 秒内重复只累加 `count`，窗口结束发一次更新（同一事件 id）；仍在重复则继续合并。P0 不防抖。爆破 / 喷洒触发后进入 10 分钟静默期，期间只计数，结束时若仍在持续发一次更新。
- P0 / P1、`oom_kill`、`service_failed`、`mem_pressure` 首次出现时附现场快照：最近 10 分钟指标（每采样间隔一点）、按 RSS 与 CPU（间隔 500 ms 两次读取）的前 5 个进程（命令行经清洗与脱敏、所属 systemd unit）。快照最多 2 秒，失败不影响事件发送。
- 事件到达后等 1 秒收集同批事件再发送（连同待发指标）；P0 立即发送。
- 外部命令只有两处：事件发生时的 `journalctl -u <unit> -n 50`（3 秒超时），以及无 auth.log / secure 时常驻的 `journalctl -f -o json`。
- 安全日志文件模式：监听目录的创建 / 改名 / 删除和文件本身的修改；logrotate 改名后继续读旧文件，直到写入方开始写新文件；copytruncate 时从头重读；位置（设备、inode、完整行末尾偏移）每 10 秒及退出时写入 state.json，重启后续读，文件已轮转时先读完 `path.1` 的余量。

### 事件级别

安全与进程事件的级别按规格 A4.2 / A3.4。规格没有逐项规定的，探针默认：

| 事件 | 级别 |
| --- | --- |
| `service_failed`、`service_start_failed`、`oom_kill`、`disk_error`、`fs_readonly` | P1 |
| `proc_segfault`、`hung_task`、`swap_thrashing`、`mem_pressure` | P2 |
| `service_recovered` | P3 |

### 与规格的差异

| 项 | 规格 | 实现 | 原因 |
| --- | --- | --- | --- |
| kmsg 时间 | `btime + ts_usec` | 当前时间减去记录的年龄（按 CLOCK_MONOTONIC 计） | 挂起或热迁移过的主机上 btime 公式偏差可达数小时（开发环境实测偏 4 小时）；探针只读新记录，按年龄换算准确 |
| `ssh_invalid_user` | 记为失败 | 只计入用户名（喷洒规则），不计失败次数 | sshd 紧接着还会记 `Failed password for invalid user …`，两者都算会让失败次数翻倍 |
| sudo 认证失败 | 每条匹配行计 1 次 | 按汇总行里的次数计（`3 incorrect password attempts` 计 3 次）；同一行带 `COMMAND=` 时仍做敏感命令判断 | sudo 每次调用只记一条汇总行；逐次的 pam_unix 行不重复计算 |
| 磁盘设备名 | `dev (\w+)` / `\((\w+)\)` | 另外识别 ext4 的 `(device sda1)` | 否则 ext4 错误拿不到设备名 |
| 防抖窗口 | 60 秒窗口关闭时发更新 | 关闭时若有重复则发更新并续一个窗口（同一 id），安静一整个窗口才结束 | 持续崩溃循环时保持同一事件，而不是每分钟一个新事件 |
| 进程巡检首轮 | 300 秒 + 偏移 | 启动后 0–30 秒先扫一轮 | 启动时已存在的问题不用等 5 分钟 |
| 服务崩溃的 `restarting` | `auto-restart` 子状态时为 true | 同左；systemd 255 上 `Restart=always` 的服务崩溃时先进入 `failed` 再重启，此时报 `restarting: false` | 按 systemd 实际发出的状态序列 |

### 实测（开发环境）

| 验收项 | 方法 | 结果 |
| --- | --- | --- |
| F4-1 `kill -SEGV` 1 秒内产生事件且信号正确 | 容器内以 systemd 为 PID 1，真实服务 | 同一秒内产生 `service_failed`，`signal: SIGSEGV`，附 journal 尾部；另测 SIGABRT、exit 203、60 秒后 `service_recovered` |
| F4-2 OOM 进程名与内存数值准确 | cgroup 内存上限 64 MB 的 python 分配内存 | `oom_kill` victim `python3`、pid、`anon_rss_mb: 67`、`scope: memcg`、`constraint: CONSTRAINT_MEMCG` 与内核一致 |
| F4-3 logrotate 前后无漏行、无重复 | 单测：改名 + 创建（旧文件仍在写）、copytruncate、停机期间轮转后重启 | 全部行恰好一次；真实主机上突破事件的失败与成功分别落在轮转前后，正确判为 P0 |
| F4-4 样本日志正确分级 | `internal/rules/testdata/auth.log` 回放 | 9 个事件类型与级别全部正确，爆破静默期结束后发更新 |
| F4-5 `bash -i >& /dev/tcp/…` 被检出 | 真实进程 | `proc_reverse_shell` P0，`remote: 127.0.0.1:4445`；1099 个进程单轮扫描 10–26 ms |
| 资源 | `scripts/agent-resource-check.sh`，全部采集器开启 | VmRSS 13.5 MB，平均 CPU 0.012% |

## 协议细节

- `machine_fp` = sha256(machine-id + token) 前 16 位。规格写的是 machine-id + server_id，但探针不知道 server_id，token 起同样的加盐作用。
- spool 文件名为 `<seq 20 位>[.<part>][.e].json.gz`，`.e` 表示含事件（淘汰时最后删除）。
- 413 只拆分未拆分过的载荷（拆成 part 1、2）；批处理阶段已按 512 KB 压缩后 / 4 MB 原始大小预先拆分，正常不会触发。
- 全新或损坏的 state.json 从当前 Unix 毫秒开始编号，保证重装后的 seq 高于服务端已记录的值（服务端按最大 seq 去重）。
- state.json 内容不变时不重复写盘。

## 本地黑匣子（阶段 11）

- 进程模型：`app` 在 `loop` 里打开本地存储（`internal/localstore`：事件 JSONL + 指标环形文件）和 Socket 服务（`internal/ipc`）；sender 只在有 token 时由 `connect()` 建立，独立模式下 batcher 的输出只保留最近一份（`xnux payload --next`），不建 spool、不发任何请求。
- 热重载：`xnux connect / disconnect` 改写 `/etc/xnux/agent.yaml`（保持 0600，只替换顶层键）后发 `reload`；守护进程重读配置，token、endpoint、proxy、TLS 变化时拆掉旧 sender、复用 spool 建新的，并立即刷出一份注册载荷，其余采集不中断。
- Socket：0660、属组 `xnux`（组不存在时仅 root 可用）；非组内用户连接得到 EACCES，命令行提示加入 `xnux` 组。请求 / 响应都是一行 JSON；单行请求超过 64 KB 即断开，同时最多 8 个连接，空闲 5 分钟断开。
- 本地健康度（`internal/localhealth`）用与服务端相同的 `xnux-shared/health` 算法：输入取最近 1 小时的分钟记录和 24 小时内事件（24 小时内的事件视为未恢复）；最近 1 小时不足 50 分钟数据时显示 "collecting"。
- CLI 资源：`xnux top` 每 2 秒一次 IPC，自身 CPU 约 0.15%。

与规格的差异：

- systemd unit 未把 `/run/xnux` 加进 `ReadWritePaths`：`RuntimeDirectory=xnux` 在 `ProtectSystem=strict` 下本来就可写，且目录在启动前才创建，写进 `ReadWritePaths` 反而会在目录缺失时启动失败。
- 规格要求安装脚本"询问是否把当前 sudo 用户加入"；只有从终端交互运行（`/dev/tty` 可读）且存在 `SUDO_USER` 时才会问，`curl | sudo sh` 在 CI 中不会卡住。

## 资源基准（F1-9）

```sh
DURATION=120 scripts/agent-resource-check.sh
```

在本地假 ingest 上运行探针并采样。开发环境（4 核 VM）实测：阶段 1 时 VmRSS 约 12.4 MB；阶段 4 开启全部事件采集器后约 13.5 MB，平均 CPU 0.012%；单次采样约 15 µs、0 分配。CI 每次跑 180 秒。阶段 7 在 6 个发行版的容器中各采样 60 秒：VmRSS 11.7–13.7 MB。阶段 11 后 CI 分别跑上报与独立两种模式（独立模式每分钟再调一次 `xnux status`），开发环境实测：上报 13.7 MB / 0.029%，独立 12.9 MB / 0.035%。透明大页为 `always` 的内核上（GitHub 的 runner 即是），Go 运行时会用 2 MB 大页承载堆，常驻内存多出 3–4 MB；守护进程发现这种情况时会带上 `GODEBUG=disablethp=1` 重新执行自身一次，实测回到 13.7 / 12.2 MB。

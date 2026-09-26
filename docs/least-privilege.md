# 最小权限部署

默认情况下探针以 root 运行（仍受 systemd 沙箱约束：`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome=read-only`、只可写 `/var/lib/xnux` 和 `/var/log/xnux`、内存上限 64 MB、CPU 上限 10%）。如果你不希望任何第三方程序以 root 身份运行，可以用专用用户加最小能力集。

## 一步完成

```sh
curl -fsSL …/install.sh | sudo sh -s -- --token xat_… --least-privilege
```

脚本会：

1. 创建系统用户 `xnux`（无 home、无登录 shell）。
2. 把 `/etc/xnux/agent.yaml` 交给 `xnux`（仍为 0600）。
3. 在 unit 中加入：

```ini
User=xnux
Group=xnux
SupplementaryGroups=systemd-journal adm     # 只加入系统上存在的组
AmbientCapabilities=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
```

`StateDirectory` / `LogsDirectory` 会由 systemd 自动改为 `xnux` 所有。已安装的机器重跑一次带 `--least-privilege` 的命令即可切换，配置保留。

## 每项权限的用途

| 权限 | 用来做什么 | 去掉后 |
| --- | --- | --- |
| `CAP_SYSLOG` | 读 `/dev/kmsg` | 没有 OOM、段错误、磁盘错误、只读文件系统、hung task 事件 |
| `CAP_DAC_READ_SEARCH` | 读 `/var/log/auth.log`、`/var/log/secure`；读其他用户进程的 `/proc/<pid>/fd` | 没有 SSH 爆破 / 登录突破 / sudo 事件（除非改用 journal）；可疑进程巡检看不到其他用户的进程 |
| `CAP_SYS_PTRACE` | `readlink` 其他用户进程的 `/proc/<pid>/exe` | 无法识别无文件进程、已删除的可执行文件、`/tmp` 下执行的程序 |
| `systemd-journal` 组 | 通过 journal 读取服务日志尾部和认证日志 | 服务崩溃事件没有日志尾部 |

探针启动时会检查每个采集器是否真的可用，不可用的自动关闭并从上报的 `capabilities` 中去掉；控制台服务器详情页会提示缺了哪些监控。资源指标（CPU、内存、磁盘、负载、温度）不需要任何特权。

## 更进一步

- 只要资源监控：在 `agent.yaml` 里关掉 `collectors.kmsg`、`authlog`、`procscan`，unit 里去掉全部能力。
- 不想让主机名出现在任何地方：`hide_hostname: true`。
- 不想让服务端知道源站 IP：用 [Cloudflare Worker 代理](relay.md)。
- 想确认它到底发了什么：[透明度](../README.md#透明度)。

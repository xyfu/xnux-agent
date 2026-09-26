# 安装探针

探针 `xnux-agent` 是一个静态链接的 Go 二进制（amd64 / arm64），支持 Linux 内核 ≥ 4.15。有 systemd 时作为服务运行；没有 systemd 也能跑，只是服务崩溃监控会自动关闭，控制台的服务器详情页会说明。

## 一行安装

不带 `--token` 即为本地[黑匣子](standalone.md)（独立模式，不联网）；要上报到 Xnux，在控制台「服务器 → 添加服务器」里复制安装命令，它已经带好 token 和上报地址：

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/install.sh | sudo sh -s -- --token xat_…
```

脚本、二进制和 `SHA256SUMS` 都来自本仓库的 [GitHub Releases](https://github.com/xyfu/xnux-agent/releases)。

脚本做的事（源码 [deploy/install.sh](../deploy/install.sh)）：

1. 按 `uname -m` 选择 amd64 / arm64，下载 `xnux-agent-linux-<arch>` 和 `SHA256SUMS`（curl 或 wget）。
2. 用 `sha256sum`（或 `shasum` / `openssl`）校验，**不一致直接退出，什么都不装**。
3. 安装到 `/usr/local/bin/xnux-agent`，建软链接 `/usr/local/bin/xnux`（命令行），创建 `xnux` 组，写 `/etc/xnux/agent.yaml`（0600）。
4. 写入加固过的 systemd unit（`NoNewPrivileges`、`ProtectSystem=strict`、`MemoryMax=64M`、`CPUQuota=10%`），启用并启动，然后运行 `xnux-agent --check` 自检。

装好后几秒内，控制台安装向导会显示收到的第一条上报原文。

### 参数

| 参数 | 作用 |
| --- | --- |
| `--token xat_…` | 控制台生成的探针 token。不带则为独立模式（只在本机记录）；升级时可省略，保留原配置 |
| `--endpoint URL` | 上报地址：服务端，或你的 [Cloudflare Worker](relay.md)。默认 `https://ingest.xnux.net` |
| `--version vX.Y.Z` | 安装指定版本（默认最新） |
| `--base-url URL` | 从这里下载二进制（Release 文件的镜像），而不是 GitHub Releases |
| `--dry-run` | 下载并校验后运行一次 `xnux-agent --dry-run --once`，把将要发送的内容打印出来；**不安装任何东西、不发送任何数据**，不需要 root |
| `--hide-hostname` | 上报的主机名一律替换为 `host` |
| `--ca-file PATH` | 上报地址使用私有 CA 时，信任该 CA |
| `--least-privilege` | 以专用用户 `xnux` + 最小能力集运行，见 [least-privilege.md](least-privilege.md) |
| `--no-start` | 安装但不启动 |
| `--add-user USER` | 把 USER 加入 `xnux` 组，免 sudo 使用 `xnux` 命令 |
| `--no-prompt` | 不询问（默认会问是否把当前 sudo 用户加入 `xnux` 组） |

### 先看看会发什么

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/install.sh | sh -s -- --dry-run
```

普通用户即可运行。输出就是探针每次上报的 JSON（已经过脱敏，替换符红底高亮），见 [payload.md](payload.md)、[redaction.md](redaction.md)。

## 升级

重新执行安装命令（可以去掉 `--token`）：替换二进制并重启服务，保留 `/etc/xnux/agent.yaml`（旧文件备份为 `agent.yaml.bak`）。探针**没有自动升级**，也没有任何远程下发指令的通道。

## 卸载

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/uninstall.sh | sudo sh               # 保留配置与数据
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/uninstall.sh | sudo sh -s -- --purge # 全部删除（含本地事件与指标、xnux 用户和组）
```

卸载后在控制台删除这台服务器，服务端会吊销 token 并硬删除它的全部数据。

## 没有 systemd 的系统

脚本会装好二进制和配置，提示你用自己的 init 系统运行：

```sh
/usr/local/bin/xnux-agent run --config /etc/xnux/agent.yaml
```

探针启动时发现没有 systemd，会关闭服务崩溃监控并在上报的 `capabilities` 中去掉 `systemd`；资源指标、内核事件、安全日志、可疑进程巡检照常工作。

## 已验证的发行版

本仓库 CI 的 `install` 任务在 Ubuntu 20.04 / 22.04 / 24.04、Debian 11 / 12、Rocky Linux 9、Alpine 3.20 上跑 [scripts/install-smoke.sh](../scripts/install-smoke.sh)：普通用户 dry-run 不安装不外发，篡改的二进制被拒。完整安装流程（安装、首条上报、升级保留配置、最小权限、`uninstall --purge`）在 Xnux 服务的 CI 中对每个发行版的 systemd 容器验证。

本地运行：

```sh
make dist && IMAGE=debian:12 scripts/install-smoke.sh
```

## 校验二进制与源码一致

发布的二进制是可复现构建（`-trimpath`、固定 Go 版本、`-buildid=`，版本和 commit 通过 `-X` 写入）：

```sh
git clone https://github.com/xyfu/xnux-agent && cd xnux-agent && git checkout vX.Y.Z
make agent VERSION=vX.Y.Z COMMIT=$(git rev-parse --short HEAD)
sha256sum bin/xnux-agent-linux-*    # 与 Release 的 SHA256SUMS 以及 /usr/local/bin/xnux-agent 对比
```

Release 里每个文件另有 cosign keyless 签名（`.sig` + `.pem`）：

```sh
cosign verify-blob --certificate xnux-agent-linux-amd64.pem --signature xnux-agent-linux-amd64.sig \
  --certificate-identity-regexp 'https://github.com/xyfu/xnux-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com xnux-agent-linux-amd64
```

CI 的 `reproducible` 任务每次都用两种方式（本机与 Go 官方镜像）构建并比对，结果逐字节相同。

## 装好之后

| 想做的事 | 命令 |
| --- | --- |
| 看状态和日志 | `systemctl status xnux-agent`、`journalctl -u xnux-agent` |
| 看刚才发了什么 | `sudo cat /var/log/xnux/last_outgoing_payload.json` |
| 与服务端收到的对比 | `sudo cat /var/log/xnux/last_outgoing_payload.sha256`，和审计台显示的哈希比较 |
| 自检 | `sudo xnux-agent --check` |
| 看生效配置 | `sudo xnux-agent --print-config`（token 只显示末 4 位） |

完整配置项见 [deploy/agent.yaml.example](../deploy/agent.yaml.example)。

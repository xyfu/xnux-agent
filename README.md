# xnux-agent

The open-source agent of [Xnux](https://xnux.net): server monitoring that captures the scene when something breaks — crashes, OOM kills, intrusions — and redacts it on the machine before anything leaves.

探针开源，数据出口可验证：你能看到每一个离开服务器的字节；我们永远拿不到你服务器的访问权限。

| | |
| --- | --- |
| `cmd/`, `internal/` | `xnux-agent`：Go，静态编译，amd64 / arm64，Linux ≥ 4.15 |
| `relay/` | Cloudflare Worker 中转：`xnux-relay`（隐藏源站 IP）和 Bark 推送中转 |
| `deploy/` | `install.sh` / `uninstall.sh`、systemd unit、配置样例 |
| `docs/` | 安装、上报字段、脱敏规则、最小权限、Worker 中转 |

上报协议和脱敏器在 [xnux-shared](https://github.com/xyfu/xnux-shared)，探针与服务端共用。License: Apache-2.0.

## 安装

在 Xnux 控制台「添加服务器」复制命令，或：

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/latest/download/install.sh | sudo sh -s -- --token xat_…
```

脚本校验 sha256 后才安装，详见 [docs/install.md](docs/install.md)。

## 透明度验证三步

| 想确认 | 怎么做 |
| --- | --- |
| 1. 探针会发什么 | `curl -fsSL …/install.sh \| sh -s -- --dry-run`（不装、不发，普通用户即可）；装好后 `sudo xnux-agent --dry-run --once` |
| 2. 刚才发了什么 | `sudo cat /var/log/xnux/last_outgoing_payload.json`，与控制台审计台显示的原文和 sha256 对比 |
| 3. 二进制是不是这份源码 | `git checkout vX.Y.Z && make agent VERSION=vX.Y.Z COMMIT=$(git rev-parse --short HEAD) && sha256sum bin/xnux-agent-linux-*`，与 Release 的 `SHA256SUMS` 对比；另有 cosign 签名 |

探针只有一个出站请求（`POST /v1/ingest`），不监听端口、不接收远程指令、没有自动升级。字段见 [docs/payload.md](docs/payload.md)，脱敏见 [docs/redaction.md](docs/redaction.md)，不想用 root 运行见 [docs/least-privilege.md](docs/least-privilege.md)，隐藏源站 IP 见 [docs/relay.md](docs/relay.md)。

## 开发

```sh
make agent            # bin/xnux-agent-linux-{amd64,arm64}
make test             # go test -race + relay tests
make lint             # golangci-lint
make dist             # everything a release publishes, with SHA256SUMS
```

实现说明与规格差异见 [docs/agent.md](docs/agent.md)。

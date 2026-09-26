# Cloudflare Worker 代理（xnux-relay）

可选。把探针的上报先发到你自己账号下的 Cloudflare Worker，再由它转给 Xnux 服务端——服务端（包括我们）只会看到 Cloudflare 的地址，看不到你服务器的源站 IP。

源码只有一个文件：[relay/src/worker.js](../relay/src/worker.js)（Apache-2.0）。每个 Release 也附带同一份文件 `xnux-relay.js`（带签名）。

## 它做什么，不做什么

| | |
| --- | --- |
| 只转发 | `POST /v1/ingest`；其他任何路径和方法都返回 404 |
| 删除的请求头 | `CF-Connecting-IP`、`CF-Connecting-IPv6`、`X-Forwarded-For`、`X-Real-IP`、`True-Client-IP`、`Forwarded`、`CF-IPCountry`、`CF-Ray`、`CF-Visitor`、`X-Forwarded-Proto`、`CDN-Loop`、`CF-EW-Via`，以及所有 `cf-` 开头的头 |
| 添加的请求头 | `X-Xnux-Relay: 1`（服务端据此标记“经 Worker”） |
| 请求体 | 流式转发，不缓冲、不解压、不查看 |
| 状态与日志 | 不用 KV / 缓存，没有 `console.log`，`wrangler.toml` 关闭了 Workers Logs |
| 上游地址 | 由环境变量 `UPSTREAM` 指定 |

`relay/test/worker.test.mjs` 覆盖以上每一条（`node --test relay/test/*.test.mjs`）。

**已知残留**：Cloudflare 会在 Worker 发出的子请求上自动附加 `CF-Worker: <zone>` 头，这是平台行为，代码无法删除。它会暴露 Worker 所在的域名，所以**请部署在与你业务无关的 `*.workers.dev` 子域上**，不要绑定自己的业务域名。

## 部署

需要一个 Cloudflare 账号（免费版即可）。

### 用 wrangler

```sh
git clone https://github.com/xyfu/xnux-agent && cd xnux-agent/relay
# wrangler.toml 里的 UPSTREAM 默认是 https://ingest.xnux.net
npx wrangler login
npx wrangler deploy
# 输出形如 https://xnux-relay.<你的子域>.workers.dev
```

### 用控制台（不装任何工具）

1. Cloudflare 控制台 → Workers & Pages → 创建 → 创建 Worker，名字随意（建议与业务无关）。
2. 编辑代码，把 `relay/src/worker.js` 的内容整段粘贴进去，部署。
3. 设置 → 变量和机密 → 添加变量 `UPSTREAM`，值为服务端地址（如 `https://ingest.xnux.net`）。
4. 设置 → 可观测性 → 关闭 Workers Logs。

控制台的安装向导里选「Worker 代理」也会给出同样的步骤和代码原文。

## 让探针走 Worker

新装：安装命令里把 `--endpoint` 换成 Worker 地址（安装向导会替你替换）：

```sh
curl -fsSL …/install.sh | sudo sh -s -- --token xat_… --endpoint 'https://xnux-relay.example.workers.dev'
```

已装：改 `/etc/xnux/agent.yaml` 的 `endpoint`，然后 `sudo systemctl restart xnux-agent`；或带新的 `--endpoint` 重跑安装命令。

## 验证

- 控制台审计台的「来源」列显示 **Cloudflare 转发**，地址是 Cloudflare 的边缘 IP。服务端用 Cloudflare 公布的 IP 段判断（启动时和每天从 `https://www.cloudflare.com/ips-v4|v6` 刷新，取不到时用内置列表）。
- 服务器列表的「连接」列显示「Worker 代理」。
- 服务端从不信任、也不记录任何 IP 类请求头；来源 IP 只取 TCP 连接的对端地址。

## Bark 中转

Bark 告警默认直接发到 `https://api.day.app`，Bark 服务器会看到 xnux 服务端的 IP。想隐藏它，可以部署仓库里的第二个 Worker：[relay/bark/worker.js](../relay/bark/worker.js)（Release 附件 `xnux-bark-relay.js`）。

- 只转发 `POST /push`，原样转发 JSON 请求体到 `UPSTREAM/push`（默认 `https://api.day.app`，也可以是自建的 bark-server）。
- 不带任何客户端请求头，只保留 `Content-Type`；没有状态和日志。
- 设置 `PATH_SECRET` 后只接受 `/<PATH_SECRET>/push`，避免被别人当作公开中转。

部署：

```sh
cd relay
npx wrangler deploy -c bark/wrangler.toml
npx wrangler secret put PATH_SECRET -c bark/wrangler.toml     # 输入一串随机字符
```

### 设备 Key 只放在 Worker 里（可选，支持群发）

把设备表存成 Worker 的加密变量 `DEVICES`，xnux 就不需要、也不保存任何设备 Key：

```sh
npx wrangler secret put DEVICES -c bark/wrangler.toml
# 输入：{"jack": "<jack 的 Key>", "ops": "<值班手机的 Key>"}
```

渠道地址末尾加 `?who=`：

| 地址 | 发给 |
| --- | --- |
| `…/<PATH_SECRET>?who=jack` | jack |
| `…/<PATH_SECRET>?who=jack,ops` | jack 和 ops |
| `…/<PATH_SECRET>?who=all` | `DEVICES` 里的所有设备 |

Worker 为每台设备各发一条。名字不存在返回 400；部分设备失败时返回 `2/3 sent; ops: …`，控制台的发送记录里能看到，错误信息里不含 Key。增删设备只需要重新设置 `DEVICES`，xnux 这边不用改。

然后在控制台「设置 → 告警渠道 → Bark」里：

| 字段 | 填写 |
| --- | --- |
| 服务器或中转地址 | `https://xnux-bark-relay.<你的子域>.workers.dev/<PATH_SECRET>` |
| Device Key | Bark App 里的 Key（也可以把 App 给出的完整链接粘到地址栏，Key 会自动拆出）；地址带 `?who=` 时留空 |

保存后点「发送测试」。xnux 会请求 `<地址>/push`，Bark 服务器只看到 Cloudflare 的地址。与探针的 Worker 一样，Cloudflare 会给子请求附加 `CF-Worker` 头，请用与业务无关的 `*.workers.dev` 子域。

## 本地试跑

不部署到 Cloudflare 也能在本机跑同一份代码（仅用于开发测试，服务端此时看到的是本机地址）：

```sh
UPSTREAM=http://localhost:8080 PORT=8787 node relay/dev.mjs
# 探针 endpoint 设为 http://<本机>:8787
```

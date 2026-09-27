# 脱敏规则

[English](redaction.md) | 简体中文

探针在本机把数据脱敏后才发出去。脱敏屏障是探针内唯一能产生外发数据的模块：发送器、镜像文件、dry-run 输出只接受 `sanitize.SanitizedPayload` 类型，而这个类型只能由 `sanitize.Seal` 构造——由 Go 类型系统在编译期保证，不靠代码审查。另有 lint 规则禁止除发送器以外的包使用 `net/http`。

实现：[xnux-shared/sanitize](https://github.com/xyfu/xnux-shared/blob/main/sanitize)（探针与服务端共用同一份代码）。

## 作用范围

对载荷中的**每一个字符串值**（包括事件数据、日志行、进程命令行、事件合并键、map 的值、数组元素）按下表顺序应用全部规则；不处理数字、布尔值和键名。单个字符串先截断到 4 KB。`hide_hostname: true` 时，所有字符串里出现的真实主机名也会换成 `host`。

探针自己生成的 `agent_version`、`kernel`、`os` 是可信字段，跳过 IP 规则（否则 `5.15.0.91` 这样的内核版本会被当成 IP）。

## 规则（按执行顺序）

长结构（私钥、JWT）先处理，避免被后面的规则切碎而漏掉。替换符是“自标记”的：审计台用 [proto/redaction_markers.json](https://github.com/xyfu/xnux-shared/blob/main/proto/redaction_markers.json) 里的正则就能找到并高亮，悬停显示规则名。

| # | 规则 | 匹配 | 替换为 |
| --- | --- | --- | --- |
| 1 | `private_key` | `-----BEGIN … PRIVATE KEY-----` 到 `-----END … PRIVATE KEY-----`（含 PGP `PRIVATE KEY BLOCK`；缺结尾时到字符串末尾） | `[REDACTED:private_key]` |
| 2 | `jwt` | `eyJ….eyJ….…` | `[REDACTED:jwt]` |
| 3 | `bearer` | `Bearer <token>` | `Bearer [REDACTED:bearer]` |
| 4 | `url_cred` | `scheme://user:password@` | `scheme://[REDACTED:cred]@` |
| 5 | `api_key` | AWS `AKIA…`、GitHub `ghp_…` / `github_pat_…`、`sk-…`、Slack `xox?-…`、Google `AIza…` | `[REDACTED:api_key]` |
| 6 | `kv_secret` | `password=…`、`secret: …`、`token …`、`api_key=…`、`client_secret=…` 等；也覆盖带前缀的名字（`MYSQL_ROOT_PASSWORD=`、`spring.datasource.password=`）和 JSON 键（`"db_password": "x"`） | 保留键名，值换成 `[REDACTED:secret]` |
| 7 | `cli_secret` | `--password=…`、`--token …`、`-pXXXX`（如 `mysql -psecret`） | `[REDACTED:secret]` |
| 8 | `email` | 邮箱地址 | 保留首字母和域名：`a***@example.com`（`sanitize.mask_email: false` 时跳过） |
| 9 | `ipv4` | 公网 IPv4 | 末段换成 `x`：`203.0.113.x` |
| 10 | `ipv6` | 公网 IPv6（2000::/3） | 保留前 3 组：`2400:cb00:1:x::` |
| 11+ | `custom` | `sanitize.extra_patterns` 中你自己的正则 | `[REDACTED:custom]` |

**不脱敏的地址**：私网和保留地址保持原样——它们对排障有用，又不暴露公网身份。IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`；IPv6：`::`、`::1`、`fc00::/7`、`fe80::/10`、`ff00::/8`、`2001:db8::/32`。

原则是“宁可误伤不可漏掉”：`v1.2.3.4` 这种看起来像 IP 的版本号也会被遮蔽；`Failed password for root` 会变成 `Failed password [REDACTED:secret] root`。

## 配置

```yaml
sanitize:
  mask_email: true          # false 时保留完整邮箱
  extra_patterns:           # 追加规则（Go RE2 正则），命中部分换成 [REDACTED:custom]
    - 'order-[0-9]{8}'
```

**内置规则不能通过配置关闭**，只能追加。

## 统计与核对

- 每条载荷的 `redactions` 字段记录各规则命中次数，审计台列表和详情都会显示。
- 本机 `/var/log/xnux/last_outgoing_payload.json` 是最近一次外发内容的明文（已脱敏），`.sha256` 是原始字节的哈希，与审计台的哈希一致即说明传输中没有被改动。
- 探针自己的日志 `/var/log/xnux/agent.log` 写入前同样经过脱敏。

## 测试

| 测试 | 内容 |
| --- | --- |
| 黄金语料 | `sanitize/testdata/*.in` / `*.want` 成对，每条规则至少 10 个正例、5 个反例；包含真实格式的 auth.log、nginx 错误日志、MySQL 启动日志、Docker 命令行 |
| 泄漏守卫 | 语料中标注为敏感的原始子串不得出现在任何输出中 |
| Fuzz | CI 每次运行 60 秒：无 panic、单次调用不超过 10 ms |
| 幂等 | 已脱敏的字符串再过一遍不变（替换符保留具体类型，不重复计数） |
| 性能 | 100 KB 载荷 < 5 ms |

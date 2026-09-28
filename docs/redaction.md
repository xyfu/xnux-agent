# Redaction rules

English | [简体中文](redaction.zh-CN.md)

The agent redacts data on the machine before sending it. The redaction barrier is the only module in the agent that can produce outbound data: the sender, the mirror file and the dry-run output accept only the `sanitize.SanitizedPayload` type, and that type can only be constructed by `sanitize.Seal`. This is guaranteed at compile time by the Go type system, not by code review. In addition, a lint rule forbids every package except the sender from using `net/http`.

Implementation: [xnux-shared/sanitize](https://github.com/xyfu/xnux-shared/blob/main/sanitize) (the agent and the server share the same code).

## Scope

All rules are applied, in the order of the table below, to **every string value** in the payload (including event data, log lines, process command lines, event merge keys, map values and array elements); numbers, booleans and key names are not processed. Each string is first truncated to 4 KB. When `hide_hostname: true`, the real hostname is also replaced with `host` wherever it appears in any string.

`agent_version`, `kernel` and `os`, which the agent generates itself, are trusted fields and skip the IP rules (otherwise a kernel version like `5.15.0.91` would be treated as an IP).

## Rules (in execution order)

Long structures (private keys, JWTs) are handled first, so that later rules cannot chop them up and let parts slip through. Redaction markers are "self-labeling": the console's transparency audit page finds and highlights them using the regexes in [proto/redaction_markers.json](https://github.com/xyfu/xnux-shared/blob/main/proto/redaction_markers.json), and shows the rule name on hover.

| # | Rule | Matches | Replaced with |
| --- | --- | --- | --- |
| 1 | `private_key` | `-----BEGIN … PRIVATE KEY-----` through `-----END … PRIVATE KEY-----` (including PGP `PRIVATE KEY BLOCK`; if the end marker is missing, through the end of the string) | `[REDACTED:private_key]` |
| 2 | `jwt` | `eyJ….eyJ….…` | `[REDACTED:jwt]` |
| 3 | `bearer` | `Bearer <token>` | `Bearer [REDACTED:bearer]` |
| 4 | `url_cred` | `scheme://user:password@` | `scheme://[REDACTED:cred]@` |
| 5 | `api_key` | AWS `AKIA…`, GitHub `ghp_…` / `github_pat_…`, `sk-…`, Slack `xox?-…`, Google `AIza…` | `[REDACTED:api_key]` |
| 6 | `kv_secret` | `password=…`, `secret: …`, `token …`, `api_key=…`, `client_secret=…`, etc.; also covers prefixed names (`MYSQL_ROOT_PASSWORD=`, `spring.datasource.password=`) and JSON keys (`"db_password": "x"`) | Key name kept, value replaced with `[REDACTED:secret]` |
| 7 | `cli_secret` | `--password=…`, `--token …`, `-pXXXX` (e.g. `mysql -psecret`) | `[REDACTED:secret]` |
| 8 | `email` | Email addresses | First letter and domain kept: `a***@example.com` (skipped when `sanitize.mask_email: false`) |
| 9 | `ipv4` | Public IPv4, also written with dashes as hostnames do (`vps-203-0-113-45.example.com`) | Last octet replaced with `x`: `203.0.113.x`, `vps-203-0-113-x.example.com`. Inside a DNS name (`static.45.113.0.203.clients.example.net`) the address may be written in reverse, so both ends are replaced: `static.x.113.0.x.clients.example.net` |
| 10 | `ipv6` | Public IPv6 (2000::/3) | First 3 groups kept: `2400:cb00:1:x::` |
| 11+ | `custom` | Your own regexes in `sanitize.extra_patterns` | `[REDACTED:custom]` |

**Addresses that are not redacted**: private and reserved addresses are left as they are; they are useful for troubleshooting and do not expose a public identity. IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`; IPv6: `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`, `2001:db8::/32`.

The principle is "better to over-redact than to leak": a version number that looks like an IP, such as `v1.2.3.4`, is masked too; `Failed password for root` becomes `Failed password [REDACTED:secret] root`.

## Configuration

```yaml
sanitize:
  mask_email: true          # false keeps full email addresses
  extra_patterns:           # extra rules (Go RE2 regexes); matched parts become [REDACTED:custom]
    - 'order-[0-9]{8}'
```

**Built-in rules cannot be turned off through configuration**; you can only add rules.

## Counts and verification

- Each payload's `redactions` field records the hit count for each rule; the console's transparency audit page shows it in both the list and the detail view.
- On the machine, `/var/log/xnux/last_outgoing_payload.json` is the plaintext (already redacted) of the most recent outbound payload, and `.sha256` is the hash of the raw bytes. If it matches the hash on the console's transparency audit page, the data was not altered in transit.
- The agent's own log, `/var/log/xnux/agent.log`, is also redacted before being written.

## Tests

| Test | Contents |
| --- | --- |
| Golden corpus | `sanitize/testdata/*.in` / `*.want` pairs, with at least 10 positive and 5 negative cases per rule; includes real-format auth.log, nginx error logs, MySQL startup logs and Docker command lines |
| Leak guard | Raw substrings marked as sensitive in the corpus must not appear in any output |
| Fuzz | 60 seconds on every CI run: no panics, no single call over 10 ms |
| Idempotence | An already-redacted string is unchanged by a second pass (redaction markers keep their specific type and are not counted twice) |
| Performance | 100 KB payload < 5 ms |

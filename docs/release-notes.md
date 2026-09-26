## 黑匣子：不连 Xnux 也能用

不带 token 安装，探针就是本机的黑匣子：持续记录指标（24 小时，1 分钟精度）和崩溃、OOM、入侵现场（30 天），出事后用 `xnux` 命令查看。**不建立任何网络连接、不发告警、免费。**

![xnux top](https://raw.githubusercontent.com/xyfu/xnux-agent/@VERSION@/docs/img/xnux-top.png)

```sh
curl -fsSL https://github.com/xyfu/xnux-agent/releases/download/@VERSION@/install.sh | sudo sh
```

| 命令 | 作用 |
| --- | --- |
| `xnux top` | 实时面板：CPU、负载、内存、磁盘、温度、Top 进程、最近事件、健康度 |
| `xnux events` / `xnux event ID` | 事件列表 / 完整现场（退出码、日志尾部、进程快照、事发前 10 分钟） |
| `xnux history` | 最近 24 小时指标折线 |
| `xnux status` | 采集器、模式、健康度扣分明细 |
| `xnux payload [--last\|--next]` | 刚才 / 下次上报的内容 |
| `xnux connect --token …` / `xnux disconnect` | 不重启地切换上报 / 独立模式 |

![xnux history](https://raw.githubusercontent.com/xyfu/xnux-agent/@VERSION@/docs/img/xnux-history.png)

说明见 [docs/standalone.md](https://github.com/xyfu/xnux-agent/blob/@VERSION@/docs/standalone.md)。

## 校验

每个文件都附 cosign 签名（`.sig` / `.pem`）；二进制可复现构建，`make agent VERSION=@VERSION@ COMMIT=<commit>` 后与 `SHA256SUMS` 对比。资源基准（上报与独立两种模式）：常驻内存 < 15 MB，空闲 CPU < 0.05%。

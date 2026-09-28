# Risk scan

English | [简体中文](risk-scan.zh-CN.md)

The Xnux agent regularly checks a few settings on your server that intruders commonly exploit. The results stay on your server and are never uploaded to Xnux. The agent uses them for one thing only: deciding which security information is worth telling you about.

## Why scan

Every server on the internet is hit by automated password guessing every day. If your server already has password login turned off, those attempts cannot succeed, and sending them to you as alerts only creates noise. An attack deserves your attention only when it could actually succeed. The scan is how the agent tells the difference.

## What is scanned

| Check | What is read |
| --- | --- |
| Whether SSH allows password login | Runs `sshd -T` to read the SSH service's effective configuration; if that is not available, reads `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/` |
| Whether root may log in with a password | Same as above |
| Whether a database is open to the internet (Redis, MongoDB, MySQL, PostgreSQL, Elasticsearch, Memcached) | The listening ports in `/proc/net/tcp` and `/proc/net/tcp6` |
| Whether the Docker API is exposed | The Docker daemon's command line (`/proc/<pid>/cmdline`) and `/etc/docker/daemon.json` |

The database ports checked are 6379 (Redis), 27017 (MongoDB), 3306 (MySQL), 5432 (PostgreSQL), 9200 (Elasticsearch) and 11211 (Memcached); a database counts as open when it listens on all interfaces (`0.0.0.0` or `::`) or on a public address. Firewall rules are not read. The Docker API counts as exposed when it is served over `tcp://` without TLS on an address other than loopback, or when something listens on port 2375.

## What is not scanned

The agent never reads: the password file (`/etc/shadow`), any private key, your application configuration files, or environment variables.

## When it scans

- When the agent starts, and once a day
- When a configuration file under `/etc/ssh/` changes (10 seconds after the last change)
- Database ports: every 5 minutes, together with the process patrol

Each scan takes a few milliseconds and does not affect server performance.

## What the results cause to be reported

| If the scan finds | Xnux starts receiving |
| --- | --- |
| SSH allows password login | SSH brute-force and password-spray events |
| root may log in with a password | The same, at a higher alert level |
| A database is open to the internet | An alert when a public address connects to that database (with the connection count and the source networks, last part hidden) |
| The Docker API is exposed | An alert when an outside address connects to the Docker API |

Whatever the scan finds, the following are always reported: a successful login after guessed passwords, a successful root login with a password, and an hourly attack summary (only the number of attempts, the number of sources and the most-tried user names).

One thing to be candid about: if Xnux receives a kind of event, it can infer that the corresponding risk exists. For example, receiving SSH brute-force events means this server allows password login. But Xnux does not hold your server's IP address, so this cannot be used to locate your server. Once a risk goes away, the agent stops the related reports automatically.

## Viewing the results

Run `xnux status` on the server to see when the last scan ran, the result of each check, and which reports are currently on because of it.

## Verifying what is actually reported

- Run `xnux-agent --dry-run` to see every piece of data that would be reported, in the terminal, without sending anything.
- Look at `/var/log/xnux/last_outgoing_payload.json`, the most recent payload actually sent.

The scan's code is fully open source, in the [`internal/riskscan`](../internal/riskscan) directory of the public [xyfu/xnux-agent](https://github.com/xyfu/xnux-agent) repository.

## Turning the risk scan off

In `/etc/xnux/agent.yaml` set:

```yaml
collectors:
  riskscan: false
```

Then restart the agent. With the scan off, the agent no longer reads the settings above. Xnux alerts only on a successful login after guessed passwords and on a successful root login with a password, and keeps receiving the hourly attack summary; brute-force, database public access and Docker API access events are no longer reported.

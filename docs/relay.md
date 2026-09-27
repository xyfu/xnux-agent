# Cloudflare Worker proxy (xnux-relay)

English | [简体中文](relay.zh-CN.md)

Optional. The agent sends its reports to a Cloudflare Worker in your own account first, which forwards them to the Xnux server. The server (including us) only ever sees a Cloudflare address, never your server's origin IP.

The source is a single file: [relay/src/worker.js](../relay/src/worker.js) (Apache-2.0). Every Release also ships the same file as `xnux-relay.js` (signed).

## What it does and doesn't do

| | |
| --- | --- |
| Forwards only | `POST /v1/ingest`; any other path or method returns 404 |
| Request headers removed | `CF-Connecting-IP`, `CF-Connecting-IPv6`, `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `Forwarded`, `CF-IPCountry`, `CF-Ray`, `CF-Visitor`, `X-Forwarded-Proto`, `CDN-Loop`, `CF-EW-Via`, and every header starting with `cf-` |
| Request headers added | `X-Xnux-Relay: 1` (the server uses it to mark requests as "via Worker") |
| Request body | Streamed through: not buffered, not decompressed, not inspected |
| State and logs | No KV / cache, no `console.log`; `wrangler.toml` disables Workers Logs |
| Upstream address | Set by the `UPSTREAM` environment variable |

`relay/test/worker.test.mjs` covers each of the above (`node --test relay/test/*.test.mjs`).

**Known leftover**: Cloudflare automatically adds a `CF-Worker: <zone>` header to subrequests made by a Worker. This is platform behavior that code cannot remove. It reveals the domain the Worker runs on, so **deploy it on a `*.workers.dev` subdomain unrelated to your business**, and don't bind it to your own business domain.

## Deployment

You need a Cloudflare account (the free plan is enough).

### With wrangler

```sh
git clone https://github.com/xyfu/xnux-agent && cd xnux-agent/relay
# UPSTREAM in wrangler.toml defaults to https://ingest.xnux.net
npx wrangler login
npx wrangler deploy
# the output looks like https://xnux-relay.<your-subdomain>.workers.dev
```

### With the dashboard (no tools to install)

1. Cloudflare dashboard → Workers & Pages → Create → Create Worker. Any name works (preferably one unrelated to your business).
2. Edit code, paste in the entire contents of `relay/src/worker.js`, and deploy.
3. Settings → Variables and Secrets → add a variable `UPSTREAM` set to the server address (e.g. `https://ingest.xnux.net`).
4. Settings → Observability → turn off Workers Logs.

Choosing **Worker proxy** in the console's install wizard gives the same steps along with the full source code.

## Pointing the agent at the Worker

New install: replace `--endpoint` in the install command with the Worker address (the install wizard does this for you):

```sh
curl -fsSL …/install.sh | sudo sh -s -- --token xat_… --endpoint 'https://xnux-relay.example.workers.dev'
```

Existing install: change `endpoint` in `/etc/xnux/agent.yaml`, then run `sudo systemctl restart xnux-agent`; or re-run the install command with the new `--endpoint`.

## Verification

- The **Source** column on the console's transparency audit page shows **Cloudflare relay**, with a Cloudflare edge IP as the address. The server decides this using Cloudflare's published IP ranges (refreshed at startup and daily from `https://www.cloudflare.com/ips-v4|v6`, falling back to a built-in list if they can't be fetched).
- The **Connection** column in the server list shows **Worker proxy**.
- The server never trusts or records any IP-type request headers; the source IP is taken only from the peer address of the TCP connection.

## Bark relay

By default Bark alerts go straight to `https://api.day.app`, and the Bark server sees the xnux server's IP. To hide it, deploy the second Worker in the repository: [relay/bark/worker.js](../relay/bark/worker.js) (Release asset `xnux-bark-relay.js`).

- Forwards only `POST /push`, passing the JSON request body unchanged to `UPSTREAM/push` (default `https://api.day.app`; it can also be a self-hosted bark-server).
- Sends none of the client's request headers except `Content-Type`; keeps no state and no logs.
- With `PATH_SECRET` set, it accepts only `/<PATH_SECRET>/push`, so others can't use it as a public relay.

Deployment:

```sh
cd relay
npx wrangler deploy -c bark/wrangler.toml
npx wrangler secret put PATH_SECRET -c bark/wrangler.toml     # enter a random string
```

### Keep device keys only in the Worker (optional, supports sending to multiple devices)

Store the device table as the Worker's encrypted variable `DEVICES`, and xnux neither needs nor stores any device keys:

```sh
npx wrangler secret put DEVICES -c bark/wrangler.toml
# enter: {"jack": "<jack's key>", "ops": "<on-call phone's key>"}
```

Append `?who=` to the channel address:

| Address | Sends to |
| --- | --- |
| `…/<PATH_SECRET>?who=jack` | jack |
| `…/<PATH_SECRET>?who=jack,ops` | jack and ops |
| `…/<PATH_SECRET>?who=all` | every device in `DEVICES` |

The Worker sends one push per device. An unknown name returns 400; if some devices fail it returns `2/3 sent; ops: …`, which shows up in the console's delivery log, and error messages never include keys. Adding or removing devices only requires setting `DEVICES` again; nothing changes on the xnux side.

Then, in the console under **Settings → Alert channels → Bark**:

| Field | Value |
| --- | --- |
| Server or relay address | `https://xnux-bark-relay.<your-subdomain>.workers.dev/<PATH_SECRET>` |
| Device Key | The key from the Bark app (you can also paste the full link the app gives you into the address field and the key is extracted automatically); leave empty when the address includes `?who=` |

Save, then click **Send test**. xnux requests `<address>/push`, and the Bark server sees only a Cloudflare address. As with the agent's Worker, Cloudflare adds a `CF-Worker` header to subrequests, so use a `*.workers.dev` subdomain unrelated to your business.

## Running locally

You can run the same code on your own machine without deploying to Cloudflare (for development and testing only; the server then sees your machine's address):

```sh
UPSTREAM=http://localhost:8080 PORT=8787 node relay/dev.mjs
# set the agent's endpoint to http://<this-machine>:8787
```

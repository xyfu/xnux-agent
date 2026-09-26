# xnux-relay

Optional Cloudflare Worker that sits between `xnux-agent` and `xnux-server` so
the server only ever sees Cloudflare IPs, never your origin IP.

- Forwards only `POST /v1/ingest`; everything else is 404.
- Removes all IP-bearing and `cf-*` headers, adds `X-Xnux-Relay: 1`.
- Stateless: no KV, no `console.log`, Workers Logs disabled.

## Deploy

1. Set `UPSTREAM` in `wrangler.toml` to your server's ingest URL.
2. `npx wrangler deploy`
3. Put the Worker URL in the agent's `endpoint`.

Known residue: Cloudflare adds a `CF-Worker: <zone>` header to subrequests.
Deploy on a `*.workers.dev` subdomain unrelated to your business domain.

Tests: `node --test relay/test/*.test.mjs`. Local run without Cloudflare:
`UPSTREAM=http://localhost:8080 node relay/dev.mjs`.

Full guide (Chinese): [docs/relay.md](../docs/relay.md).

// Runs the Worker under Node for local testing, without Cloudflare:
//
//   UPSTREAM=http://localhost:8080 PORT=8787 node relay/dev.mjs
//
// Not for production: Node is not Cloudflare, and the point of the relay
// is that the server sees Cloudflare's addresses, not yours.
import { createServer } from "node:http";
import { Readable } from "node:stream";
import worker from "./src/worker.js";

const env = { UPSTREAM: process.env.UPSTREAM ?? "http://localhost:8080" };
const port = Number(process.env.PORT ?? 8787);

// Node's fetch needs duplex for streamed request bodies; Workers do not.
const nodeFetch = globalThis.fetch;
globalThis.fetch = (url, init) => nodeFetch(url, { ...init, duplex: "half" });

createServer(async (req, res) => {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  const request = new Request(`http://${req.headers.host}${req.url}`, {
    method: req.method,
    headers,
    body: hasBody ? Readable.toWeb(req) : undefined,
    duplex: "half",
  });
  try {
    const out = await worker.fetch(request, env);
    res.writeHead(out.status, Object.fromEntries(out.headers));
    res.end(Buffer.from(await out.arrayBuffer()));
  } catch (e) {
    res.writeHead(502).end(String(e));
  }
}).listen(port, () => process.stderr.write(`xnux-relay (dev) on :${port} → ${env.UPSTREAM}\n`));

// Run with: node --test relay/test
import assert from "node:assert/strict";
import { test } from "node:test";
import worker from "../src/worker.js";

const UPSTREAM = "https://ingest.example.com";

function capture() {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(null, { status: 202 });
  };
  return calls;
}

const post = (path, headers = {}, body = "payload") =>
  new Request(`https://relay.example.workers.dev${path}`, { method: "POST", headers, body });

test("only POST /v1/ingest is forwarded", async () => {
  const calls = capture();
  for (const req of [
    new Request("https://relay.example.workers.dev/v1/ingest"),
    post("/v1/ingest/"),
    post("/v1/servers"),
    post("/"),
    new Request("https://relay.example.workers.dev/v1/ingest", { method: "PUT", body: "x" }),
  ]) {
    const res = await worker.fetch(req, { UPSTREAM });
    assert.equal(res.status, 404, `${req.method} ${new URL(req.url).pathname}`);
  }
  assert.equal(calls.length, 0);
});

test("IP-bearing and cf-* headers are removed, the rest pass through", async () => {
  const calls = capture();
  const res = await worker.fetch(
    post("/v1/ingest", {
      Authorization: "Bearer xat_secret",
      "Content-Type": "application/json",
      "Content-Encoding": "gzip",
      "User-Agent": "xnux-agent/1.0.0",
      "CF-Connecting-IP": "203.0.113.9",
      "CF-Connecting-IPv6": "2001:db8::9",
      "X-Forwarded-For": "203.0.113.9",
      "X-Real-IP": "203.0.113.9",
      "True-Client-IP": "203.0.113.9",
      Forwarded: "for=203.0.113.9",
      "CF-IPCountry": "DE",
      "CF-Ray": "abc-FRA",
      "CF-Visitor": '{"scheme":"https"}',
      "X-Forwarded-Proto": "https",
      "CDN-Loop": "cloudflare",
      "CF-EW-Via": "15",
      "CF-Something-New": "x",
    }),
    { UPSTREAM },
  );
  assert.equal(res.status, 202);
  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, `${UPSTREAM}/v1/ingest`);
  assert.equal(init.method, "POST");
  const h = init.headers;
  assert.equal(h.get("authorization"), "Bearer xat_secret");
  assert.equal(h.get("content-encoding"), "gzip");
  assert.equal(h.get("user-agent"), "xnux-agent/1.0.0");
  assert.equal(h.get("x-xnux-relay"), "1");
  for (const [k, v] of h) {
    assert.ok(!k.startsWith("cf-"), `leaked ${k}`);
    assert.ok(!v.includes("203.0.113.9") && !v.includes("2001:db8::9"), `leaked IP in ${k}`);
  }
  for (const k of ["x-forwarded-for", "x-real-ip", "true-client-ip", "forwarded", "x-forwarded-proto", "cdn-loop"]) {
    assert.equal(h.get(k), null, k);
  }
});

test("the body is streamed, not buffered", async () => {
  const calls = capture();
  const req = post("/v1/ingest");
  await worker.fetch(req, { UPSTREAM });
  assert.equal(calls[0].init.body, req.body);
});

test("the worker keeps no state and writes no logs", async () => {
  const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/worker.js", import.meta.url), "utf8"));
  assert.ok(!/console\./.test(src), "console call in worker");
  assert.ok(!/\bKV\b|caches\.|env\.[A-Z_]+\.(put|get)\(/.test(src), "storage access in worker");
});

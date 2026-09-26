// Run with: node --test relay/test/*.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import worker from "../bark/worker.js";

// Fake Bark upstream: records calls; keys listed in `bad` are rejected.
function capture(bad = []) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const body = typeof init.body === "string" ? JSON.parse(init.body) : null;
    calls.push({ url, init, body });
    if (body && bad.includes(body.device_key)) {
      return new Response(JSON.stringify({ code: 400, message: `device key ${body.device_key} not found` }), { status: 400 });
    }
    return new Response('{"code":200,"message":"success"}', { status: 200 });
  };
  return calls;
}

const push = (path, headers = {}, body = { device_key: "k", title: "t", body: "b" }) =>
  new Request(`https://bark-relay.example.workers.dev${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const DEVICES = JSON.stringify({ jack: "KEY-JACK", ops: "KEY-OPS", mom: "KEY-MOM" });

test("forwards only POST /push, with no client or IP headers", async () => {
  const calls = capture();
  const res = await worker.fetch(
    push("/push", { "CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.9", "User-Agent": "xnux-notify/1" }),
    {},
  );
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.day.app/push");
  assert.deepEqual([...new Headers(calls[0].init.headers).keys()], ["content-type"]);
  for (const r of [push("/"), push("/push/x"), new Request("https://w.example/push")]) {
    assert.equal((await worker.fetch(r, {})).status, 404);
  }
  assert.equal(calls.length, 1);
});

test("PATH_SECRET closes the relay; UPSTREAM picks the Bark server", async () => {
  const calls = capture();
  const env = { PATH_SECRET: "s3cret", UPSTREAM: "https://bark.example.org/" };
  assert.equal((await worker.fetch(push("/push"), env)).status, 404);
  assert.equal((await worker.fetch(push("/wrong/push"), env)).status, 404);
  assert.equal((await worker.fetch(push("/s3cret/push"), env)).status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://bark.example.org/push");
});

test("?who= sends to the named devices, with keys kept in the Worker", async () => {
  const calls = capture();
  const noKey = { title: "[P1] web-01", body: "b", level: "timeSensitive" };
  let res = await worker.fetch(push("/push?who=jack,ops", {}, noKey), { DEVICES });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { code: 200, message: "success", sent: 2 });
  assert.deepEqual(calls.map((c) => c.body.device_key).sort(), ["KEY-JACK", "KEY-OPS"]);
  assert.ok(calls.every((c) => c.body.title === "[P1] web-01" && c.body.level === "timeSensitive"));

  calls.length = 0;
  res = await worker.fetch(push("/push?who=all", {}, { ...noKey, device_key: "from-xnux" }), { DEVICES });
  assert.equal(res.status, 200);
  // Every device, and a key sent by the caller is ignored.
  assert.deepEqual(calls.map((c) => c.body.device_key).sort(), ["KEY-JACK", "KEY-MOM", "KEY-OPS"]);
});

test("unknown names and failed devices are reported without keys", async () => {
  let calls = capture();
  let res = await worker.fetch(push("/push?who=jack,nobody"), { DEVICES });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /unknown device: nobody/);
  assert.equal(calls.length, 0);

  calls = capture(["KEY-OPS"]);
  res = await worker.fetch(push("/push?who=all"), { DEVICES });
  const j = await res.json();
  assert.equal(res.status, 502);
  assert.equal(j.code, 502);
  assert.match(j.message, /^2\/3 sent; ops: device key \*\*\*\* not found$/);
  assert.ok(!j.message.includes("KEY-"));
  assert.equal(calls.length, 3);

  res = await worker.fetch(push("/push?who=all"), { DEVICES: "{not json" });
  assert.equal(res.status, 500);
  res = await worker.fetch(push("/push?who=all"), {});
  assert.equal(res.status, 400); // no DEVICES: nobody to notify
});

test("keeps no state and writes no logs", async () => {
  const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../bark/worker.js", import.meta.url), "utf8"));
  assert.ok(!/console\./.test(src));
});

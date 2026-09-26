// xnux Bark relay: a stateless Cloudflare Worker between xnux-server and a
// Bark server, so Bark sees Cloudflare's address instead of the server's.
//
// Only POST <prefix>/push is forwarded, to UPSTREAM + "/push" (default
// https://api.day.app), with the JSON body and nothing else: no client
// headers, no IP headers. With PATH_SECRET set, the prefix must be
// /<PATH_SECRET>, so the Worker is not an open relay.
//
// Device keys can live here instead of in xnux: put them in the DEVICES
// secret as JSON, {"jack": "<key>", "ops": "<key>"}, and give the channel
// a server URL ending in ?who=jack, ?who=jack,ops or ?who=all. xnux then
// sends no device key at all, and each named device gets the message.
// Without ?who= the request is passed through with its own device_key.

const JSON_TYPE = { "Content-Type": "application/json; charset=utf-8" };

function reply(code, message, extra = {}) {
  return new Response(JSON.stringify({ code, message, ...extra }), { status: code, headers: JSON_TYPE });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const want = env.PATH_SECRET ? `/${env.PATH_SECRET}/push` : "/push";
    if (req.method !== "POST" || url.pathname !== want) {
      return new Response("not found", { status: 404 });
    }
    const upstream = (env.UPSTREAM || "https://api.day.app").replace(/\/+$/, "") + "/push";

    const who = url.searchParams.get("who");
    if (!who) {
      return fetch(upstream, { method: "POST", headers: JSON_TYPE, body: req.body });
    }

    let devices;
    try {
      devices = JSON.parse(env.DEVICES || "{}");
    } catch {
      return reply(500, "DEVICES is not valid JSON");
    }
    const names = who.trim() === "all" ? Object.keys(devices) : who.split(",").map((s) => s.trim()).filter(Boolean);
    if (names.length === 0) return reply(400, "no devices to notify");
    const unknown = names.filter((n) => !Object.hasOwn(devices, n));
    if (unknown.length) return reply(400, `unknown device: ${unknown.join(", ")}`);

    let msg;
    try {
      msg = await req.json();
    } catch {
      return reply(400, "the body must be JSON");
    }
    delete msg.device_key;
    delete msg.device_keys;

    const failed = (
      await Promise.all(
        names.map(async (name) => {
          const key = devices[name];
          try {
            const r = await fetch(upstream, { method: "POST", headers: JSON_TYPE, body: JSON.stringify({ ...msg, device_key: key }) });
            const j = await r.json().catch(() => ({}));
            if (r.ok && j.code === 200) return null;
            return `${name}: ${String(j.message || `HTTP ${r.status}`).replaceAll(key, "****")}`;
          } catch (e) {
            return `${name}: ${String(e && e.message).replaceAll(key, "****")}`;
          }
        }),
      )
    ).filter(Boolean);
    if (failed.length) {
      return reply(502, `${names.length - failed.length}/${names.length} sent; ${failed.join("; ")}`);
    }
    return reply(200, "success", { sent: names.length });
  },
};

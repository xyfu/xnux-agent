// xnux-relay: stateless Cloudflare Worker that forwards agent payloads to
// xnux-server while stripping every header that could reveal the origin IP
// (spec A8.5). It keeps no state and writes no logs.

const STRIP = [
  "cf-connecting-ip", "cf-connecting-ipv6", "x-forwarded-for", "x-real-ip",
  "true-client-ip", "forwarded", "cf-ipcountry", "cf-ray", "cf-visitor", "x-forwarded-proto",
  "cdn-loop", "cf-ew-via",
];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method !== "POST" || url.pathname !== "/v1/ingest") {
      return new Response("not found", { status: 404 });
    }
    const headers = new Headers();
    for (const [k, v] of req.headers) {
      const key = k.toLowerCase();
      if (!STRIP.includes(key) && !key.startsWith("cf-")) headers.set(k, v);
    }
    headers.set("X-Xnux-Relay", "1");
    return fetch(env.UPSTREAM + "/v1/ingest", { method: "POST", headers, body: req.body });
  },
};

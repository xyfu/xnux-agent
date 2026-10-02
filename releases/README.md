# Release notes

Every release has `notes/{version}.json` (the version without `v`), added in
the pull request that makes the change:

```json
{
  "level": "recommended",
  "highlights": {
    "zh-Hans": ["一句话说明变化"],
    "en": ["One sentence per change"]
  }
}
```

- `level`: `security` (a security fix: the console notifies once per server),
  `recommended` or `optional` (shown on the server page only).
- `highlights`: what users get, one sentence each, in both languages.

CI checks every notes file (`go run ./scripts/manifest check`). Tagging
`vX.Y.Z` builds `manifest.json` from all notes files and attaches it to the
release, with this release's downloads and checksums; the Xnux service
reads it from `releases/latest/download/manifest.json` to tell users about
updates (spec v1.1 delta 12). With the `XNUX_MANIFEST_KEY` secret set (base64
of a 32-byte ed25519 seed) the manifest is also signed
(`manifest.json.ed25519`).

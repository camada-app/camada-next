# Changelog

## Unreleased

### Added

- `challengeGate(req, render)`: with a render callback it returns the challenge Response, or `await render()` with the middleware's signal (`x-camada-challenge: 1`, no-store on `cache-control` and the CDN cache headers) applied when the request is not a page load. A route that forces a challenge no longer has to set those headers itself for an API client. `challengeGate(req)` is unchanged. (camada-all-1q7x)

## 0.4.0 (2026-10-26; follows 0.3.2)

Built against `@camada/core` 0.6.0 (customer `matches` rules on the linear-time re2js engine inside a per-request regex budget; the beacon relay strips SDK-attested keys) and `@camada/browser` 0.4.0.

### Security

- `ja4` is now read from `x-vercel-ja4-digest` only when the `VERCEL` env var is set. Off Vercel (self-hosted Next, another proxy) a client could set that header and forge the TLS fingerprint. A self-hosted deploy that loads a `vercel env pull` `.env.local` (`VERCEL=1`) still forwards it; the analyst counts sdk-next ja4 for its own tenant only either way. (camada-all-av1f)

### Fixed

- The route-handler beacon relay now stamps `rts` (the relay's receive time) on each `sig:1` row, after the body, so a browser cannot set it. edge-analyst prefers a bounded `rts` over the browser `ts`; every other relay already sent it. (camada-all-10fg)
- A signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`,
  `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and
  `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of
  `cache-control`, so an app-set one could still let a shared cache keep the per-client copy.
  (camada-all-5pog)

## 0.3.2 (2026-10-12; follows 0.3.1)

Needs the `@camada/core` that exports `readBodyCapped`.

### Fixed

- Block responses (path, ip, asn, country, tls and rule blocks, the `Forbidden` 403) now send `cache-control: no-store`, like the challenge answers, so a shared cache cannot serve one visitor's block to others. (camada-all-8lp6)
- The challenge page (middleware, `challengeGate()`, and the page re-issued after a wrong answer)
  sends its own `Content-Security-Policy` (core's `challengePageCsp()`: only its inline solver
  and style, by hash), as the other adapters' pages do. (camada-all-mwpo)
- `camadaRoute()`'s `fp` relay and challenge verify read the body through core's `readBodyCapped`:
  a chunked (length-less) POST is cut off at the 32 KB / 4 KB cap and its stream cancelled,
  instead of being read whole first. The client sees `413`, or a connection reset where the Node
  server stops reading the upload. `fp` had no cap check before the read at all, and the
  challenge cap now counts bytes, not UTF-16 units (camada-all-4u4i).
- `fp` reads its body only after the block and beacon-off checks, so a blocked client gets its
  `403` with no body pulled, and an inert route reads none.

### Docs

- README: without a socket peer this adapter keeps the `X-Forwarded-For` walk and so trusts
  the host's edge; lock the origin to it.

### Changed

- The `exports` map now gives `require` its own `.d.cts` declarations (`import` and `require` each carry a `types` condition), so a CommonJS TypeScript app on `moduleResolution: node16` compiles; CI runs `@arethetypeswrong/cli`. (camada-all-vuzm)

## 0.3.1 (2026-10-09; follows 0.3.0)

Needs `@camada/core` 0.5.1.

### Fixed

- The snapshot client no longer re-polls back to back when `/snapshot` fails. It keeps its blocks and
  waits max(`retry-after`, 5 s), capped at the refresh interval (through `@camada/core` 0.5.1,
  camada-all-pbv9).

## 0.3.0 (2026-10-04; follows 0.2.0)

### Changed

- `engines.node` is `>=20` (was `>=18`). npm only warns on an older Node unless `engine-strict`
  is set.
- The default ingest is `https://in.camada.app` (was `https://in.camada.dev`). `in.camada.dev`
  still answers as an alias, so apps on 0.2.0 keep shipping. `CAMADA_INGEST_URL` still overrides
  it.
- `ts` is the request start.
- The middleware's events still ship before the route answers, with `st` and `dur` null. Use
  `withCamada` where you want both.

### Fixed

- The middleware no longer stamps `x-rid` on, or ships a row for, camada's own beacon routes (`GET /api/camada/b.js`,
  `POST /api/camada/fp`), as the other SDKs' beacon routes carry neither. Enforcement still applies.

### Added

- `withCamada(handler)` wraps a route handler. It enforces as the middleware does (verdict,
  block, challenge, the `_sfp` session) and ships one event with the real status and a `dur`
  from the request start: to the last byte for a `text/event-stream` body, and to the moment the
  handler returned (time to first byte) for anything else. A thrown `redirect()` or `notFound()`
  reports the status Next answers with, and the response carries `x-rid`. Leave wrapped routes out of the middleware matcher. If the
  middleware matches anyway, its signed `x-camada-mw` mark spares the second event and cookie;
  enforcement always runs. See the README's threat model.

### Fixed

- Path rules match the canonical path (through `@camada/core` 0.5.0). A percent-encoded,
  upper-cased or trailing-slash spelling of a blocked path used to slip past the block.
- `track()` inside a `withCamada` route uses the wrapper's request id and session and ignores a
  client-sent `x-camada-rid`. The middleware drops client-sent `x-camada-rid` and `x-camada-mw`
  headers on every path it forwards.
- A runtime without WebCrypto only loses the `x-camada-mw` mark, not the pass-through and the
  session cookie.

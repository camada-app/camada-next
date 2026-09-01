# @camada/next

camada backend SDK for Next.js (app router): edge-safe middleware/proxy enforcement, the
`/api/camada` route handlers that serve the fingerprint beacon first-party, and a
`<CamadaBeacon/>` server component carrying the request's `rid`. Implements plan.md
INT-2/INT-3 for the Next.js position. Not yet published to npm; consumed via `file:`
dependencies from sibling checkouts.

## Install

Three files, one env var:

```ts
// middleware.ts (Next ≤15) or proxy.ts (Next 16) at the project root
import { camada } from '@camada/next';
export default camada();
export const config = { matcher: ['/((?!_next/|favicon.ico).*)'] };
```

```ts
// app/api/camada/[...camada]/route.ts
import { camadaRoute } from '@camada/next';
export const { GET, POST } = camadaRoute();
```

```tsx
// app/layout.tsx — in <head>
import { CamadaBeacon } from '@camada/next';
<CamadaBeacon />
```

```
CAMADA_KEY=<ingest_token>.<snap_token>
```

Optional env: `CAMADA_INGEST_URL` (default `https://in.camada.dev`), `CAMADA_SNAPSHOT_URL`
(default ingest + `/snapshot`), `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N |
cidrs:a,b`), `CAMADA_DISABLED=1` (kill switch, checked per request). Unconfigured, the SDK
is inert: the middleware returns `undefined`, the route handlers answer 404/204, and one
rate-limited `console.error` says why.

## What each piece does

- **`camada()`** — the middleware: refreshes the blocklist snapshot off-path
  (`event.waitUntil`), enforces it inline (403 with `x-block-reason`/`x-block-version`;
  blocked requests always ship, unsampled), stamps `x-camada-rid` onto the forwarded request
  and `x-rid` onto the response, and ships the wire event fire-and-forget with tap
  `sdk-next`. On Vercel, `x-vercel-ja4-digest` — a real TLS fingerprint — rides along as
  `ja4`.
- **`camadaRoute()`** — `GET …/b.js` serves the `@camada/browser` IIFE first-party (no CSP
  or ad-blocker friction); `POST …/fp` relays the beacon body to ingest with the
  trusted-proxy-resolved client IP and `tap: 'sdk-next'` injected. Works on both runtimes.
- **`<CamadaBeacon/>`** — async server component; reads the middleware's `x-camada-rid` via
  `next/headers` and renders `<script src="/api/camada/b.js?r=<rid>" async>` so the beacon
  POST joins the server-side wire event.

## Edge-runtime safety

The middleware's entire import graph is Web-APIs-only — no `node:` imports. This is
**proven, not promised**: `test/edge-safety.test.ts` bundles `src/middleware.ts` for a bare
edge target (where `node:` built-ins do not resolve — a canary test pins that the mechanism
trips) and then executes the bundle inside `@edge-runtime/vm` with no Node globals, driving
a real cold → blocked flow against the golden snapshot fixture.

## Documented caveats (honest limits of this position)

- **Client IP needs a trusted-proxy config.** There is no socket peer in middleware, so with
  no `CAMADA_TRUSTED_PROXY` (and no server-delivered tenant config) the IP resolves to
  `null` and IP rules simply don't enforce — a spoofed `X-Forwarded-For` can never reach the
  blocklist. When `VERCEL` is set and no override is given, the SDK defaults to
  `{mode:'vercel'}` (Vercel overwrites XFF, so its rightmost entry is trustworthy).
- **Header order is alphabetical.** The edge runtime sorts request headers, so `hord` is
  sorted at this tap (still shipped; the scorer's capability mask knows `sdk-next` lacks the
  raw-wire-order signal `@camada/node` has).
- **Events ship pre-response** (`st: null`, like the edge collector's tap) — middleware
  cannot see the final status. Blocked requests ship with `st: 403`.
- **Serverless cold start fails open**: the first request on a cold instance sees no
  snapshot and passes; the snapshot loads via `waitUntil` and enforcement begins on the next
  request.
- **App-context tracking** (`track()` — login failed, signup, …) is a `@camada/node` feature
  today; the Next.js app-context surface lands later.

## Develop

```
npm install && npm run build && npm test && npm run check
```

Sibling checkouts `camada-core`, `camada-browser`, `camada-react` must exist and be built
(`file:` dependencies). The middleware behavior suite runs under the vitest `edge-runtime`
environment; route handlers run under node.

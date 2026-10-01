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

Optional env: `CAMADA_INGEST_URL` (default `https://in.camada.app`), `CAMADA_SNAPSHOT_URL`
(default ingest + `/snapshot`), `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N |
cidrs:a,b`), `CAMADA_DISABLED=1` (kill switch, checked per request). Unconfigured, the SDK
is inert: the middleware returns `undefined`, the route handlers answer 404/204, and one
rate-limited `console.error` says why.

## What each piece does

- **`camada()`** — the middleware: refreshes the blocklist snapshot off-path
  (`event.waitUntil`), enforces it inline (403 with
  `x-block-reason`/`x-block-version`/`x-block-rule`; blocked requests always ship,
  unsampled), stamps `x-camada-rid` onto the forwarded request
  and `x-rid` onto the response, and ships the wire event fire-and-forget with tap
  `sdk-next`. On Vercel, `x-vercel-ja4-digest` — a real TLS fingerprint — rides along as
  `ja4`.
- **`camadaRoute()`** — `GET …/b.js` serves the `@camada/browser` IIFE first-party (no CSP
  or ad-blocker friction); `POST …/fp` relays the beacon body to ingest with the
  trusted-proxy-resolved client IP and `tap: 'sdk-next'` injected. Works on both runtimes.
  Both endpoints go inert (404) when the project turns the beacon off in its settings.
- **`<CamadaBeacon/>`** — async server component; reads the middleware's `x-camada-rid` via
  `next/headers` and renders `<script src="/api/camada/b.js?r=<rid>" async>` so the beacon
  POST joins the server-side wire event.

## Status and duration: `withCamada()`

The middleware runs before your route, so its event ships pre-response with `st` and `dur`
null, and that traffic shows on the IP timeline as points without a duration. To report both
for a route handler, wrap it:

```ts
// app/api/data/route.ts
import { withCamada } from '@camada/next';
export const GET = withCamada(async (req) => Response.json(await load()));
```

```ts
// proxy.ts: leave wrapped routes out of the matcher, so each request is recorded once
export const config = { matcher: ['/((?!_next/|favicon.ico|api/data$).*)'] };
```

End each excluded route with `$`. Without it the exclusion is a prefix match: `api/data` also
takes `/api/database`, `/api/data-export` and `/api/data/anything` out of the middleware, and
a route left out of the matcher is protected only by its own `withCamada()`. If it isn't
wrapped, it gets no blocks, no challenges and no events. To exclude a wrapped route and its
sub-routes, use `api/data(?:/|$)`, and wrap all of them.

The wrapper does what the middleware does (verdict, block, challenge, the `_sfp` session) and
ships one event with the real status and `dur`: request start to the response, and to the last
byte for a streamed `text/event-stream` body. A thrown `redirect()` or `notFound()` reports the status
Next answers with. The event flushes once the body has gone out. On a serverless host the
wrapper holds the function open for it with Next's `after()` (Next 15.1+), or with the request
context's `waitUntil` on older versions. `track()` does the same.

If the middleware also matched the request, it has already shipped an event, and the wrapper
skips its own (it logs a rate-limited hint, and that request has no `dur`).

**Threat model.** Every request header can come from the client. A route left out of the
matcher never sees the middleware, and Next has no server-only channel from the middleware to
a route handler (on Vercel they run in different processes). So:

- The wrapper enforces on every request. Verdict, block and challenge never depend on a header.
- The one thing a header decides is whether to skip the second event. The middleware stamps
  `x-camada-mw` on the request it forwards: a timestamp and an HMAC, under your server-only
  `CAMADA_KEY`, of that timestamp, the method, the path and query, the rid and
  `X-Forwarded-For`. The wrapper accepts it for 30 seconds and compares in constant time.
- The middleware deletes any `x-camada-mw` the client sent before it forwards a request.
- A forged mark doesn't verify. A leaked one (the rid is in the `x-rid` response header, and
  the mark rides the forwarded request headers into anything that logs or proxies them)
  doesn't verify on another path, query or method, from another client chain, or after 30 s.
  Within those bounds, the most a replay can do is hide its own event. It still gets blocked
  or challenged, and that ships an event.
- A middleware rewrite, or a proxy that changes `X-Forwarded-For` between the middleware and
  the function, makes the mark fail. That costs a second event, never enforcement.

Pages and server components have no handler to wrap and keep the middleware's pre-response
event. A wrapped route has no `x-camada-rid`, so `track()` inside it joins on the session only,
and the Vercel `ja4` header is not sent from this position.

## Custom rules

Your Rules page holds one ordered list per project, and the middleware walks it before the
allow, block and challenge lists. First match wins — the order *is* the precedence — and each
rule carries one of four actions:

| action | what the middleware does | on the event |
|---|---|---|
| `skip` | passes the request | nothing |
| `block` | `403` before your app | `blk: "rule"`, `rl: "<rule id>"` |
| `challenge` | serves the proof-of-work page (`CAMADA_CHALLENGE=0` opts out) | `blk: "challenge"` |
| `warn` | passes the request and marks it for the analyst | `wrn: "<rule id>"` |

A skip rule also carries a *record matches* flag, which only the analyst reads: a recorded skip
is still scored and shows on your dashboard as Allowed, an unrecorded one is dropped before
scoring. Either way the request passes here, unstamped — the built-in Allow-list is a skip rule
with recording on.

A rule block also names the row that decided, so the response says which rule to edit:

```
HTTP/1.1 403 Forbidden
x-block-reason: rule
x-block-rule: cr_4f2a9c1b7e03
```

`ip`, `path`, `ua` and `header` conditions enforce here; `asn`, `country` and `tlsx` conditions
cannot be judged at this position and fail open, so a rule that needs one never matches. A
`header` condition (`is`, `contains`, `matches`) reads the name case-insensitively, and headers
are the request plane's alone — the analyst never sees them, so a header rule is enforced by a
v5 SDK like this one or not at all.

The rules ride the v5 snapshot, which the SDK asks for by default. A project that has not
published the container you ask for is answered with the next one down, so asking for the
newest is always safe.

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
- **Middleware events ship pre-response** (`st` and `dur` null, like the edge collector's
  tap): middleware cannot see the final status. Wrap a route handler in `withCamada()` to
  report both (above). Blocked requests ship with `st: 403` and `blk: <reason>`
  (ip4|ip6|path|rule); the beacon route handlers ship the same event when they deny. Every
  snapshot poll and event batch carries `x-camada-sdk: @camada/next/<version>`.
- **Serverless cold start fails open**: the first request on a cold instance sees no
  snapshot and passes; the snapshot loads via `waitUntil` and enforcement begins on the next
  request.
- **App-context tracking works from request scope only.** `track(event, {user?})` records
  outcomes (login failed, signup, …) from server actions, route handlers, and server
  components, joining the middleware's wire event via `x-camada-rid` + the `_sfp` cookie and
  HMAC-hashing the identifier in-process. Outside a request scope it is a silent no-op —
  and it must not be called from middleware, which already ships its own event.

## Develop

```
npm install && npm run build && npm test && npm run check
```

Sibling checkouts `camada-core`, `camada-browser`, `camada-react` must exist and be built
(`file:` dependencies). The middleware behavior suite runs under the vitest `edge-runtime`
environment; route handlers run under node.

## Matcher requirement

The middleware/proxy matcher decides where enforcement runs. The beacon route handlers
(`/api/camada/*`) enforce the blocklist themselves, so blocked clients can never fetch the
beacon even when your matcher excludes `/api/` — but every OTHER route your matcher excludes
is invisible to camada: no blocking, no events. Keep the matcher as broad as the example's
(`/((?!_next/|favicon.ico).*)`) unless you have a specific reason not to. Anchor every exclusion
with `$` (see `withCamada()` above): an unanchored lookahead entry is a prefix match.

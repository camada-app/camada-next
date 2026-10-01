# Changelog

## 0.3.0 (unreleased; follows 0.2.0)

### Changed

- `engines.node` is `>=20` (was `>=18`). npm only warns on an older Node unless `engine-strict`
  is set.
- The default ingest is `https://in.camada.app` (was `https://in.camada.dev`). `in.camada.dev`
  still answers as an alias, so apps on 0.2.0 keep shipping. `CAMADA_INGEST_URL` still overrides
  it.
- `ts` is the request start.
- The middleware's events still ship before the route answers, with `st` and `dur` null. Use
  `withCamada` where you want both.

### Added

- `withCamada(handler)` wraps a route handler. It enforces as the middleware does (verdict,
  block, challenge, the `_sfp` session) and ships one event with the real status and a `dur`
  from the request start: to the last byte for a `text/event-stream` body, and to the moment the
  handler returned (time to first byte) for anything else. A thrown `redirect()` or `notFound()`
  reports the status Next answers with. Leave wrapped routes out of the middleware matcher. If the
  middleware matches anyway, its signed `x-camada-mw` mark spares the second event and cookie;
  enforcement always runs. See the README's threat model.

### Fixed

- `track()` inside a `withCamada` route uses the wrapper's request id and session and ignores a
  client-sent `x-camada-rid`. The middleware drops client-sent `x-camada-rid` and `x-camada-mw`
  headers on every path it forwards.
- A runtime without WebCrypto only loses the `x-camada-mw` mark, not the pass-through and the
  session cookie.

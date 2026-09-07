// The Next.js middleware/proxy entry: enforce the blocklist inline, stamp x-camada-rid onto
// the forwarded request (the <CamadaBeacon/> server component reads it back), ship the wire
// event fire-and-forget. Everything runs inside a try/catch fail-open envelope — a camada
// bug must never break the customer's app (plan.md INT-2).
//
// MUST stay edge-runtime-safe: Web APIs only (fetch/Headers/Request/Response/URL/crypto),
// no node: imports anywhere in this entry's import graph. Proven by test/edge-safety.test.ts,
// which bundles this file for a bare edge runtime and executes it inside @edge-runtime/vm.
// NextRequest/NextFetchEvent are imported as TYPES only; NextResponse comes from
// 'next/server', which is itself edge-safe.
import type { NextFetchEvent, NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { resolveClientIp, logRateLimited, guardedAsync } from '@camada/core';
import { getEngine, isDisabled, challengeEnabled, trustedProxy, type Engine } from './engine';
import { isChallengeRoute, challengePassed, serveChallenge } from './challenge';
import { buildEvent, cookieValue, SESSION_COOKIE } from './event';

export interface CamadaMiddlewareOptions {
  // Reserved. The engine is configured via CAMADA_* environment variables.
}

/** Next accepts a promise here; only the challenge branch returns one (it awaits WebCrypto). */
export type MiddlewareResult = Response | undefined | Promise<Response | undefined>;

/** The ordinary path: ship one pre-response event, stamp the rid, mint the session cookie.
 *  `warnRule` is the id of the `warn` rule that let this request through, if one did (§D3). */
function capture(engine: Engine, req: NextRequest, path: string, ip: string | null, existingSid: string | null, warnRule: string | null, waitUntil?: (p: Promise<unknown>) => void): Response {
  const rid = crypto.randomUUID();
  const sid = existingSid ?? crypto.randomUUID();
  const cfg = engine.snap.config;
  const excluded = (cfg?.exclude || []).some((x) => path.startsWith(x));
  if (!excluded && Math.random() < (cfg?.sample ?? 1)) {
    // st stays null: middleware ships pre-response, like the edge collector's tap.
    const ev = buildEvent(req, path, ip, rid, sid, !existingSid);
    if (warnRule) ev.wrn = warnRule;
    engine.queue.push(ev);
    engine.queue.flush(waitUntil);
  }

  const headers = new Headers(req.headers);
  headers.set('x-camada-rid', rid);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('x-rid', rid);
  if (!existingSid) {
    const secure = new URL(req.url).protocol === 'https:' ? '; Secure' : '';
    res.headers.append('set-cookie', `${SESSION_COOKIE}=${sid}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${secure}`);
  }
  return res;
}

/**
 * `export default camada();` from middleware.ts (Next ≤15) / proxy.ts (Next 16).
 * Returns undefined (Next continues) whenever camada is disabled, unconfigured, or broken.
 */
export function camada(_options?: CamadaMiddlewareOptions): (req: NextRequest, event: NextFetchEvent) => MiddlewareResult {
  return function camadaMiddleware(req: NextRequest, event: NextFetchEvent): MiddlewareResult {
    try {
      if (isDisabled()) return undefined;
      const engine = getEngine();
      if (!engine) return undefined;
      const waitUntil = event?.waitUntil ? (p: Promise<unknown>) => event.waitUntil(p) : undefined;
      engine.snap.ensureFresh(waitUntil);

      // There is no socket peer at the edge: with no trusted-proxy config (or no XFF) the
      // ip resolves to null and ip rules simply don't enforce — a spoofed X-Forwarded-For
      // can never reach the blocklist. On Vercel the engine defaults to {mode:'vercel'}.
      const ip = resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));
      const path = new URL(req.url).pathname;

      // the same _sfp session as the collector and @camada/node: sid/ns comparable across taps
      const existingSid = cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE);

      // The custom rules read the user agent and the request headers (§D3); without them every
      // `ua` and `header` condition is false. `Headers.get` is case-insensitive, so the
      // lower-cased name the matcher asks with finds whatever spelling the client sent.
      const v = engine.snap.verdict({
        ip, path, ua: req.headers.get('user-agent'), header: (n) => req.headers.get(n),
      });   // cold start fails open ('cold')
      if (v.block) {
        const ev = buildEvent(req, path, ip, crypto.randomUUID(), existingSid, false);
        ev.st = 403;                                 // blocked requests always ship, unsampled
        ev.blk = v.reason;                           // SDK-01: the reason rides the event so the analyst counts SDK blocks, not the app's own 403s ('rule' when a rule decided)
        if (v.rule) ev.rl = v.rule;
        engine.queue.push(ev);
        engine.queue.flush(waitUntil);
        const headers: Record<string, string> = {
          'content-type': 'text/plain',
          'x-block-reason': String(v.reason ?? ''),
          'x-block-version': v.version ?? '',
        };
        if (v.rule) headers['x-block-rule'] = v.rule;   // a custom rule blocked: name it, so the customer knows which row to edit
        return new Response('Forbidden', { status: 403, headers });
      }
      // `warn` passes the request and only marks its event; a skip passes with nothing
      // stamped — it is the absence of enforcement.
      const warnRule = v.warn ? v.rule ?? null : null;

      // A challenge verdict: serve the proof-of-work page unless this client already passed.
      // The verify route answers its own endpoint, so never challenge that path. A challenge
      // needs a resolved ip (the nonce and `_cch` are bound to it) — without one, fail open,
      // the same stance ip rules take at this position.
      // A client that HAS passed falls through to the normal capture path: it keeps its rid,
      // its session cookie and its event, so an hour of `_cch` is not an hour of blindness.
      // guardedAsync covers the whole branch — the synchronous catch below cannot see a
      // rejection from these awaits, and WebCrypto is not guaranteed to exist.
      if (v.challenge && ip && challengeEnabled() && !isChallengeRoute(path)) {
        return guardedAsync(async () => (
          (await challengePassed(engine, req, ip))
            ? capture(engine, req, path, ip, existingSid, warnRule, waitUntil)
            : serveChallenge(engine, req, ip, path + new URL(req.url).search, waitUntil)
        ), undefined);
      }

      return capture(engine, req, path, ip, existingSid, warnRule, waitUntil);
    } catch (err) {
      logRateLimited(err);   // fail open: the app proceeds as if camada were not installed
      return undefined;
    }
  };
}

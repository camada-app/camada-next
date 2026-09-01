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
import { buildWireEvent, resolveClientIp, logRateLimited, TAP_NEXT, type WireEvent } from '@camada/core';
import { getEngine, isDisabled, trustedProxy } from './engine';

export interface CamadaMiddlewareOptions {
  // Reserved. The engine is configured via CAMADA_* environment variables.
}

/**
 * `export default camada();` from middleware.ts (Next ≤15) / proxy.ts (Next 16).
 * Returns undefined (Next continues) whenever camada is disabled, unconfigured, or broken.
 */
export function camada(_options?: CamadaMiddlewareOptions): (req: NextRequest, event: NextFetchEvent) => Response | undefined {
  return function camadaMiddleware(req: NextRequest, event: NextFetchEvent): Response | undefined {
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

      const v = engine.snap.verdict({ ip, path });   // cold start fails open ('cold')
      if (v.block) {
        const ev = buildEvent(req, path, ip, crypto.randomUUID());
        ev.st = 403;                                 // blocked requests always ship, unsampled
        engine.queue.push(ev);
        engine.queue.flush(waitUntil);
        return new Response('Forbidden', {
          status: 403,
          headers: {
            'content-type': 'text/plain',
            'x-block-reason': String(v.reason ?? ''),
            'x-block-version': v.version ?? '',
          },
        });
      }

      const rid = crypto.randomUUID();
      const cfg = engine.snap.config;
      const excluded = (cfg?.exclude || []).some((x) => path.startsWith(x));
      if (!excluded && Math.random() < (cfg?.sample ?? 1)) {
        // st stays null: middleware ships pre-response, like the edge collector's tap.
        engine.queue.push(buildEvent(req, path, ip, rid));
        engine.queue.flush(waitUntil);
      }

      const headers = new Headers(req.headers);
      headers.set('x-camada-rid', rid);
      const res = NextResponse.next({ request: { headers } });
      res.headers.set('x-rid', rid);
      return res;
    } catch (err) {
      logRateLimited(err);   // fail open: the app proceeds as if camada were not installed
      return undefined;
    }
  };
}

function buildEvent(req: NextRequest, path: string, ip: string | null, rid: string): WireEvent {
  const url = new URL(req.url);
  return buildWireEvent(
    {
      method: req.method,
      host: req.headers.get('host') ?? url.host,
      path,
      query: url.search,
      // The edge runtime sorts header names, so hord is alphabetical at this tap — still
      // shipped; the scorer knows sdk-next lacks the raw-wire-order signal (capability mask).
      headers: [...req.headers.entries()],
      ip,
      httpVersion: null,   // not observable in middleware
    },
    { tap: TAP_NEXT, rid, ja4: req.headers.get('x-vercel-ja4-digest') },
  );
}

// Route handlers for app/api/camada/[...camada]/route.ts:
//   GET  …/b.js  -> the first-party beacon IIFE (its auto-init derives the fp endpoint from
//                   the script URL's final path segment and the rid from ?r=)
//   POST …/fp    -> queue the beacon as a sig:1 row with the trusted-proxy-resolved client IP
//                   and tap 'sdk-next': it rides the event batch (one request per flush at the
//                   analyst, not one per page view) — the mirror of @camada/node's /_cam/*.
// Works on BOTH runtimes (edge and node): Web APIs only, no node: imports. Unconfigured or
// disabled: GET 404s, POST answers 204 and drops — inert, never an error.
import iife from '@camada/browser/iife-string';
import { guardedAsync, resolveClientIp, TAP_NEXT } from '@camada/core';
import { getEngine, isDisabled, challengeEnabled, trustedProxy, type Engine } from './engine';
import { verifyChallenge } from './challenge';
import { buildEvent, cookieValue, SESSION_COOKIE } from './event';

const FP_MAX = 32 * 1024;   // matches the server's /fp cap: never accept what ingest will 413
const encoder = new TextEncoder();

const notFound = () => new Response(null, { status: 404 });
const noContent = () => new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

// The route handlers enforce too: a middleware matcher that excludes /api/ (a common pattern)
// must not leave the beacon endpoints serving blocked clients.
function blocked(engine: Engine, req: Request): Response | null {
  const ip = resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));
  const path = new URL(req.url).pathname;
  // §D3: `ua` and `header` rules need these; `Headers.get` already matches names case-insensitively
  const v = engine.snap.verdict({ ip, path, ua: req.headers.get('user-agent'), header: (n) => req.headers.get(n) });
  if (!v.block) return null;
  const ev = buildEvent(req, path, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
  ev.st = 403; ev.blk = v.reason;   // SDK-01: a beacon-route deny is a block like any other — it ships, unsampled
  if (v.rule) ev.rl = v.rule;
  engine.queue.push(ev);
  void engine.queue.flush();
  const headers: Record<string, string> = { 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '' };
  if (v.rule) headers['x-block-rule'] = v.rule;
  return new Response('Forbidden', { status: 403, headers });
}

function lastSegment(req: Request): string {
  const parts = new URL(req.url).pathname.split('/');
  return parts[parts.length - 1];
}

function activeEngine(): Engine | null {
  return isDisabled() ? null : getEngine();
}

export function camadaRoute(): {
  GET: (req: Request) => Promise<Response>;
  POST: (req: Request) => Promise<Response>;
} {
  return {
    GET: (req) => guardedAsync(async () => {
      if (lastSegment(req) !== 'b.js') return notFound();
      const engine = activeEngine();
      if (!engine) return notFound();
      engine.snap.ensureFresh();
      const deny = blocked(engine, req);
      if (deny) return deny;
      if (engine.snap.config?.beacon === false) return notFound();   // tenant disabled the beacon
      return new Response(iife, {
        status: 200,
        headers: { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' },
      });
    }, notFound()),

    POST: (req) => guardedAsync(async () => {
      if (lastSegment(req) === 'challenge') {
        const engine = activeEngine();
        if (!engine || !challengeEnabled()) return notFound();
        engine.snap.ensureFresh();
        const deny = blocked(engine, req);   // a blocked client cannot buy its way past with a solution
        if (deny) return deny;
        return verifyChallenge(engine, req);
      }
      if (lastSegment(req) !== 'fp') return notFound();
      const body = await req.text();
      if (encoder.encode(body).byteLength > FP_MAX) return new Response(null, { status: 413 });
      const engine = activeEngine();
      if (engine) {
        engine.snap.ensureFresh();
        const deny = blocked(engine, req);
        if (deny) return deny;
        if (engine.snap.config?.beacon === false) return notFound();   // tenant disabled the beacon: stand fp down as well as b.js
        const ip = resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));
        let parsed: unknown;
        try { parsed = JSON.parse(body); } catch { return noContent(); }   // not a beacon: drop it, never ship junk
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          engine.queue.push({ ...(parsed as Record<string, unknown>), sig: 1, ip, tap: TAP_NEXT });
          void engine.queue.flush();   // fire-and-forget, as the relay was: a serverless runtime may freeze right after the response
        }
      }
      return noContent();
    }, noContent()),
  };
}

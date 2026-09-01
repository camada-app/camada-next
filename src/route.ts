// Route handlers for app/api/camada/[...camada]/route.ts:
//   GET  …/b.js  -> the first-party beacon IIFE (its auto-init derives the fp endpoint from
//                   the script URL's final path segment and the rid from ?r=)
//   POST …/fp    -> relay the beacon body to ingest with the trusted-proxy-resolved client
//                   IP and tap 'sdk-next' injected — the mirror of @camada/node's /_cam/*.
// Works on BOTH runtimes (edge and node): Web APIs only, no node: imports. Unconfigured or
// disabled: GET 404s, POST answers 204 and drops — inert, never an error.
import iife from '@camada/browser/iife-string';
import { guardedAsync, resolveClientIp, TAP_NEXT } from '@camada/core';
import { getEngine, isDisabled, trustedProxy, type Engine } from './engine';

const FP_MAX = 64 * 1024;

const notFound = () => new Response(null, { status: 404 });
const noContent = () => new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

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
      if (engine.snap.config?.beacon === false) return notFound();   // tenant disabled the beacon
      return new Response(iife, {
        status: 200,
        headers: { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' },
      });
    }, notFound()),

    POST: (req) => guardedAsync(async () => {
      if (lastSegment(req) !== 'fp') return notFound();
      const body = await req.text();
      if (new TextEncoder().encode(body).byteLength > FP_MAX) return new Response(null, { status: 413 });
      const engine = activeEngine();
      if (engine) {
        engine.snap.ensureFresh();
        const ip = resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));
        let out = body;
        try { out = JSON.stringify({ ...JSON.parse(body), tap: TAP_NEXT }); } catch { /* relay as-is; the server validates */ }
        void engine.fetchImpl(`${engine.env.ingestUrl}/fp`, {   // fire-and-forget
          method: 'POST',
          headers: { 'x-tenant': engine.env.ingestToken, 'content-type': 'application/json', 'x-client-ip': ip || '' },
          body: out,
          signal: AbortSignal.timeout(2000),
        }).catch(() => {});
      }
      return noContent();
    }, noContent()),
  };
}

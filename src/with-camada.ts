// withCamada(handler): the route-handler position, where the response is visible. The middleware
// runs before the route and ships its event pre-response (st and dur null); a wrapped route
// handler runs @camada/core's fetch pipeline itself (verdict, block, challenge, the session) and
// ships one event with the real status and a dur up to the response (a text/event-stream body to its last byte).
//
// Threat model. Every request header can come from the client: the middleware does not run for a
// route left out of its matcher, and Next offers no server-only channel from the middleware to the
// route (on Vercel they run in different processes, often different regions). So:
//   - Enforcement here never depends on a header. Verdict, block and challenge run on every request.
//   - The one thing a header may decide is whether this request's event already shipped. Wrapped
//     routes belong outside the matcher; if the middleware ran anyway it stamps `x-camada-mw`, an
//     HMAC under the server-only CAMADA_KEY of a timestamp, the method, the path and query, the rid
//     and X-Forwarded-For. A mark that verifies within 30 s skips the second event and the second
//     session cookie, nothing else. A copied mark fails on another path, query, method or client
//     and after the window; within it, it can at most hide a replay's event, never pass a block.
//   - The middleware strips any x-camada-mw the client sent before forwarding.
//   - track() inside the handler takes this wrapper's rid and session (withTrackScope), never a
//     client-sent x-camada-rid; only a request the middleware already shipped keeps its stamped one.
import iife from '@camada/browser/iife-string';
import { logRateLimited, TAP_NEXT } from '@camada/core';
import { createFetchCamada, withSetCookie } from '@camada/core/fetch';
import { envSource, getEngine } from './engine';
import { VERIFY_PATH } from './challenge';
import { middlewareMarkValid } from './event';
import { requestWaitUntil } from './wait-until';
import { withTrackScope } from './track';
import { SDK_ID } from './version';

const cam = createFetchCamada({ tap: TAP_NEXT, sdk: SDK_ID, iife }, { challengePath: VERIFY_PATH });   // lazy mode: edge and serverless

async function middlewareShipped(req: Request): Promise<boolean> {
  const secret = getEngine()?.env.secret;
  return !!secret && (await middlewareMarkValid(secret, req));
}

/** Next's redirect() / notFound() throw an error whose digest ends in the status they answer with. */
const thrownStatus = (err: unknown): number =>
  Number(/;(\d{3});?$/.exec(String((err as { digest?: unknown } | null)?.digest ?? ''))?.[1] ?? 500);

/**
 * `export const GET = withCamada(async (req) => Response.json(...))` in a route.ts. Same
 * CAMADA_* env as the middleware; inert without a key or with CAMADA_DISABLED=1. Never breaks
 * the handler: a camada failure costs the event, not the response.
 */
export function withCamada<R extends Request, A extends unknown[]>(
  handler: (req: R, ...rest: A) => Response | Promise<Response>,
): (req: R, ...rest: A) => Promise<Response> {
  return async (req, ...rest) => {
    const env = envSource();
    // On Vercel the platform overwrites X-Forwarded-For, so its rightmost entry is trustworthy: the middleware's default too.
    const r = await cam.before(req, {
      env: { ...env, CAMADA_TRUSTED_PROXY: env.CAMADA_TRUSTED_PROXY || (env.VERCEL ? 'vercel' : undefined) },
      waitUntil: requestWaitUntil(),   // the event flushes after the body: hold a serverless function open for it
    });
    if (!r) return handler(req, ...rest);
    if (r.response) return r.response;   // block, challenge: whatever headers the request carries
    let shipped = false;
    try { shipped = await middlewareShipped(req); } catch (err) { logRateLimited(err); }
    if (shipped) {
      logRateLimited(new Error(`withCamada: the middleware also matched ${new URL(req.url).pathname}, so its pre-response event stands and dur is not reported; exclude wrapped routes from the matcher`));
      return handler(req, ...rest);   // and its _sfp cookie: no second session
    }
    let res: Response;
    try {
      res = await withTrackScope({ rid: r.vars.rid, sid: r.vars.sid }, () => handler(req, ...rest));
    } catch (err) {
      cam.after(req, r.vars, thrownStatus(err));
      throw err;
    }
    res = withRid(res, r.vars.rid);
    return cam.finish(req, r.vars, r.vars.sessionCookie ? withSetCookie(res, r.vars.sessionCookie) : res);
  };
}

/** x-rid, the rid of this request's row, the same header the middleware stamps. Set in place, or on a copy when the
 *  headers are immutable (`Response.redirect()`, a `fetch()` result), as withSetCookie does: same status and body.
 *  A 101 upgrade is left alone. Not on a request the middleware shipped: its own x-rid, that row's, reaches the client. */
function withRid(res: Response, rid: string): Response {
  if (res.status === 101) return res;
  try {
    res.headers.set('x-rid', rid);
    return res;
  } catch {
    // ponytail: core's copyResponse is not exported; its Deno and @hono/node-server cases never reach a Next route.
    const out = new Response(res.body, res);
    out.headers.set('x-rid', rid);
    return out;
  }
}

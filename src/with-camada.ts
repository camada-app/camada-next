// withCamada(handler): the route-handler position, where the response is visible. The middleware
// runs before the route and ships its event pre-response (st and dur null); a wrapped route
// handler runs @camada/core's fetch pipeline itself (verdict, block, challenge, the session) and
// ships one event with the real status and a dur that covers the body, streamed or not.
//
// One request, one event: list wrapped routes outside the middleware matcher. If the middleware
// ran anyway it has already shipped, which the signed `x-camada-mw` header it stamps on the
// forwarded request proves; the wrapper then steps aside rather than count the request twice.
// The header is an HMAC of the rid, so a client cannot forge it to slip past the wrapper.
import iife from '@camada/browser/iife-string';
import { safeEqual, logRateLimited, TAP_NEXT } from '@camada/core';
import { createFetchCamada, withSetCookie } from '@camada/core/fetch';
import { envSource, getEngine } from './engine';
import { VERIFY_PATH } from './challenge';
import { MW_HEADER, middlewareMark } from './event';
import { SDK_ID } from './version';

const cam = createFetchCamada({ tap: TAP_NEXT, sdk: SDK_ID, iife }, { challengePath: VERIFY_PATH });   // lazy mode: edge and serverless

async function middlewareRan(req: Request): Promise<boolean> {
  const mark = req.headers.get(MW_HEADER);
  const rid = req.headers.get('x-camada-rid');
  const secret = getEngine()?.env.secret;
  return !!(mark && rid && secret && safeEqual(mark, await middlewareMark(secret, rid)));
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
    let ran = false;
    try { ran = await middlewareRan(req); } catch (err) { logRateLimited(err); }
    if (ran) {
      logRateLimited(new Error(`withCamada: the middleware also matched ${new URL(req.url).pathname}, so its pre-response event stands and dur is not reported; exclude wrapped routes from the matcher`));
      return handler(req, ...rest);
    }
    const env = envSource();
    // On Vercel the platform overwrites X-Forwarded-For, so its rightmost entry is trustworthy: the middleware's default too.
    const r = await cam.before(req, { env: { ...env, CAMADA_TRUSTED_PROXY: env.CAMADA_TRUSTED_PROXY || (env.VERCEL ? 'vercel' : undefined) } });
    if (!r) return handler(req, ...rest);
    if (r.response) return r.response;   // block, challenge
    let res: Response;
    try {
      res = await handler(req, ...rest);
    } catch (err) {
      cam.after(req, r.vars, thrownStatus(err));
      throw err;
    }
    return cam.finish(req, r.vars, r.vars.sessionCookie ? withSetCookie(res, r.vars.sessionCookie) : res);
  };
}

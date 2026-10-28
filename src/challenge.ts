// The challenge for @camada/next (SDK-04). Edge-runtime-safe: Web APIs and WebCrypto only, no
// node: imports — this module sits in the middleware's import graph, which
// test/edge-safety.test.ts bundles for a bare edge runtime.
//
// The page is served by the middleware (or by challengeGate() from a route the app gates
// itself) and posts a form to POST /api/camada/challenge, handled by camadaRoute().
import {
  createChallengeAsync, challengePage, challengePageCsp, challengeCookie, safeReturnTo, wantsHtml, parseFormBody,
  resolveClientIp, readBodyCapped, CHALLENGE_COOKIE, type AsyncChallengeKit,
} from '@camada/core';
import { getEngine, isDisabled, challengeEnabled, trustedProxy, type Engine } from './engine';
import { buildEvent, cookieValue, middlewareMarkValid, SESSION_COOKIE } from './event';

/** Where the page posts. The catch-all route handler must be mounted at /api/camada/[...camada]
 *  (the documented install) — the served page hard-codes this action. */
export const VERIFY_PATH = '/api/camada/challenge';

const BODY_MAX = 4 * 1024;   // the verify form is ~120 bytes; anything larger is not ours

/** The app may mount the catch-all elsewhere, so the middleware matches on the tail. */
export const isChallengeRoute = (path: string): boolean => /\/camada\/challenge\/?$/.test(path);

// One kit per engine; the engine is replaced wholesale by configure(), so the map never grows.
const kits = new WeakMap<Engine, AsyncChallengeKit>();
export function kitFor(engine: Engine): AsyncChallengeKit {
  let k = kits.get(engine);
  if (!k) { k = createChallengeAsync({ secret: engine.env.secret }); kits.set(engine, k); }
  return k;
}

export const clientIp = (engine: Engine, req: Request): string | null =>
  resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));

export function challengePassed(engine: Engine, req: Request, ip: string): Promise<boolean> {
  return kitFor(engine).tokenValid(ip, Date.now(), cookieValue(req.headers.get('cookie') || '', CHALLENGE_COOKIE));
}

/** 403 + the proof-of-work page (HTML navigations) or 403 JSON (a Pages Router data request), plus the
 *  `blk: "challenge"` event — a served challenge is reported like a block (contract §D2). */
export async function serveChallenge(engine: Engine, req: Request, ip: string, target: string, waitUntil?: (p: Promise<unknown>) => void, ship = true): Promise<Response> {
  if (ship) {
    const ev = buildEvent(req, new URL(req.url).pathname, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
    ev.st = 403;
    ev.blk = 'challenge';
    engine.queue.push(ev);
    engine.queue.flush(waitUntil);
  }

  // A page gets the proof-of-work page; the only other request served here is a Pages Router data request, which Next turns into a document load.
  if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
    return new Response('{"error":"challenge_required"}', {
      status: 403,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
    });
  }
  const html = challengePage({ nonce: await kitFor(engine).nonce(ip, Date.now()), action: VERIFY_PATH, to: safeReturnTo(target) });
  return new Response(html, {
    status: 403,
    // the page's own policy (its inline solver and style by hash), never one the app sets (camada-all-mwpo)
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1', 'content-security-policy': challengePageCsp() },
  });
}

/** POST handler for `…/camada/challenge`: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
export async function verifyChallenge(engine: Engine, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const ip = clientIp(engine, req);
  const kit = kitFor(engine);
  // camada answers this path before the app runs, so it must not become a place to post
  // hundreds of megabytes at an unauthenticated endpoint.
  const body = await readBodyCapped(req, BODY_MAX);
  if (body === null) return new Response(null, { status: 413 });
  const form = parseFormBody(body);
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!ip || !(await kit.verify(ip, now, form.nonce, form.solution))) {
    const html = ip ? challengePage({ nonce: await kit.nonce(ip, now), action: url.pathname, to }) : 'Forbidden';
    const headers: Record<string, string> = { 'content-type': ip ? 'text/html; charset=utf-8' : 'text/plain', 'cache-control': 'no-store' };
    if (ip) headers['content-security-policy'] = challengePageCsp();
    return new Response(html, { status: 403, headers });
  }
  const ev = buildEvent(req, url.pathname, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
  ev.st = 200;
  ev.ch = 1;   // challenge passed (contract §A3 ingest field)
  engine.queue.push(ev);
  void engine.queue.flush();
  return new Response(null, {
    status: 302,
    headers: {
      location: to,
      'set-cookie': challengeCookie(await kit.issue(ip, now), url.protocol === 'https:'),
      'cache-control': 'no-store',
    },
  });
}

/** Only a page or a Pages Router data request (`x-nextjs-data: 1`; Next turns its non-ok answer into a hard navigation) is
 *  challenged. Any other request passes, signalled (82ar). App Router soft navigations are among them: Next strips the RSC
 *  header (and `_rsc`) before middleware runs, so they cannot be told from a fetch; the next document load meets the page. */
export function isChallengeable(req: Request): boolean {
  return wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest')) || req.headers.get('x-nextjs-data') === '1';
}

/** Per-client signal: no shared cache may keep the copy. CDNs read their own header ahead of cache-control. */
const NO_STORE_HEADERS = ['cache-control', 'cdn-cache-control', 'surrogate-control', 'cloudflare-cdn-cache-control', 'vercel-cdn-cache-control', 'netlify-cdn-cache-control'];

/** `x-camada-challenge: 1` plus no-store: the signal on a non-HTML request that passed under a challenge (82ar). */
export function signalChallenge(h: Headers): void {
  h.set('x-camada-challenge', '1');
  for (const n of NO_STORE_HEADERS) h.set(n, 'no-store');
}

/** Edit `res`'s headers in place, or a copy's when they are immutable (`Response.redirect()`, a `fetch()` result): same
 *  status and body. A 101 upgrade is left alone. */
export function editHeaders(res: Response, edit: (h: Headers) => void): Response {
  if (res.status === 101) return res;
  try {
    edit(res.headers);
    return res;
  } catch {
    // ponytail: core's copyResponse is not exported; its Deno and @hono/node-server cases never reach a Next route.
    const out = new Response(res.body, res);
    edit(out.headers);
    return out;
  }
}

/** For a route that wants to gate itself (the example's /challenge-me): the challenge Response,
 *  or, once this client already holds a valid `_cch`, the route's own.
 *
 *  One request, one event. The middleware stamps `x-camada-rid` and its `x-camada-mw` proof on
 *  the request it forwards, so a mark that verifies means the middleware already shipped this
 *  request's row (a client-sent rid alone proves nothing); the gate then serves
 *  the page WITHOUT a second row, which would double-count the request at the analyst. Exclude
 *  the gated route from the middleware matcher and the gate ships the `blk: "challenge"` row
 *  itself — that is the configuration to use when you want the challenge counted.
 *
 *  `challengeGate(req)` returns null when the route should render normally. `challengeGate(req, render)` returns the
 *  challenge Response or `await render()`. A request that is not challengeable gets the middleware's signal on that
 *  render (`x-camada-challenge: 1`, no-store on `cache-control` and the CDN cache headers), overriding the app's.
 *  The gate ships one `chs: 1` row only when there is no valid middleware mark (the middleware did not see the
 *  request) and the ip has no valid `_cch`; with a valid mark it ships nothing. */
export function challengeGate(req: Request): Promise<Response | null>;
export function challengeGate(req: Request, render: () => Response | Promise<Response>): Promise<Response>;
export async function challengeGate(req: Request, render?: () => Response | Promise<Response>): Promise<Response | null> {
  const { res, signal } = await gate(req);
  if (res || !render) return res;
  const out = await render();
  return signal ? editHeaders(out, signalChallenge) : out;
}

async function gate(req: Request): Promise<{ res: Response | null; signal: boolean }> {
  const pass = { res: null, signal: false };
  if (isDisabled() || !challengeEnabled()) return pass;
  const engine = getEngine();
  if (!engine) return pass;
  const challengeable = isChallengeable(req);
  const ip = clientIp(engine, req);
  if (!ip || await challengePassed(engine, req, ip)) return pass;   // unidentifiable client: fail open
  const url = new URL(req.url);
  const shipped = await middlewareMarkValid(engine.env.secret, req).catch(() => false);
  if (!challengeable) {
    // Not challenged (82ar): the route continues. Unless the middleware saw this request (valid mark), ship its chs: 1 event here.
    if (!shipped) {
      const ev = buildEvent(req, url.pathname, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
      ev.chs = 1;
      engine.queue.push(ev);
      engine.queue.flush();
    }
    return { res: null, signal: true };
  }
  return { res: await serveChallenge(engine, req, ip, url.pathname + url.search, undefined, !shipped), signal: false };
}

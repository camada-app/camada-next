// The challenge for @camada/next (SDK-04). Edge-runtime-safe: Web APIs and WebCrypto only, no
// node: imports — this module sits in the middleware's import graph, which
// test/edge-safety.test.ts bundles for a bare edge runtime.
//
// The page is served by the middleware (or by challengeGate() from a route the app gates
// itself) and posts a form to POST /api/camada/challenge, handled by camadaRoute().
import {
  createChallengeAsync, challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody,
  resolveClientIp, CHALLENGE_COOKIE, type AsyncChallengeKit,
} from '@camada/core';
import { getEngine, isDisabled, challengeEnabled, trustedProxy, type Engine } from './engine';
import { buildEvent, cookieValue, SESSION_COOKIE } from './event';

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

/** 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
 *  `blk: "challenge"` event — a served challenge is reported like a block (contract §D2). */
export async function serveChallenge(engine: Engine, req: Request, ip: string, target: string, waitUntil?: (p: Promise<unknown>) => void, ship = true): Promise<Response> {
  if (ship) {
    const ev = buildEvent(req, new URL(req.url).pathname, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
    ev.st = 403;
    ev.blk = 'challenge';
    engine.queue.push(ev);
    engine.queue.flush(waitUntil);
  }

  if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
    return new Response('{"error":"challenge_required"}', {
      status: 403,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
    });
  }
  const html = challengePage({ nonce: await kitFor(engine).nonce(ip, Date.now()), action: VERIFY_PATH, to: safeReturnTo(target) });
  return new Response(html, {
    status: 403,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
  });
}

/** POST handler for `…/camada/challenge`: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
export async function verifyChallenge(engine: Engine, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const ip = clientIp(engine, req);
  const kit = kitFor(engine);
  // camada answers this path before the app runs, so it must not become a place to post
  // hundreds of megabytes at an unauthenticated endpoint.
  if (Number(req.headers.get('content-length')) > BODY_MAX) return new Response(null, { status: 413 });
  const body = await req.text();
  if (body.length > BODY_MAX) return new Response(null, { status: 413 });
  const form = parseFormBody(body);
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!ip || !(await kit.verify(ip, now, form.nonce, form.solution))) {
    const html = ip ? challengePage({ nonce: await kit.nonce(ip, now), action: url.pathname, to }) : 'Forbidden';
    return new Response(html, { status: 403, headers: { 'content-type': ip ? 'text/html; charset=utf-8' : 'text/plain', 'cache-control': 'no-store' } });
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

/** For a route that wants to gate itself (the example's /challenge-me): the challenge Response,
 *  or null when this client already holds a valid `_cch` and the route should render normally.
 *
 *  One request, one event. The middleware stamps `x-camada-rid` on the request it forwards, so
 *  its presence means the middleware already shipped this request's row; the gate then serves
 *  the page WITHOUT a second row, which would double-count the request at the analyst. Exclude
 *  the gated route from the middleware matcher and the gate ships the `blk: "challenge"` row
 *  itself — that is the configuration to use when you want the challenge counted. */
export async function challengeGate(req: Request): Promise<Response | null> {
  if (isDisabled() || !challengeEnabled()) return null;
  const engine = getEngine();
  if (!engine) return null;
  const ip = clientIp(engine, req);
  if (!ip || await challengePassed(engine, req, ip)) return null;   // unidentifiable client: fail open
  const url = new URL(req.url);
  return serveChallenge(engine, req, ip, url.pathname + url.search, undefined, !req.headers.has('x-camada-rid'));
}

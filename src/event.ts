// One wire-event builder for every @camada/next entry (middleware + beacon route). Web APIs
// only: this sits in the middleware's edge-safe import graph.
import { buildWireEvent, hmacHex, safeEqual, TAP_NEXT, type WireEvent } from '@camada/core';

export function buildEvent(req: Request, path: string, ip: string | null, rid: string, sid: string | null, newSession: boolean): WireEvent {
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
      httpVersion: null,   // not observable at this position
    },
    { tap: TAP_NEXT, rid, sid, newSession, ja4: req.headers.get('x-vercel-ja4-digest') },
  );
}

/** Stamped by the middleware next to x-camada-rid on the request it forwards: proof, for withCamada(), that this request's
 *  event already shipped. It only ever spares the wrapper a second event; enforcement never depends on it. */
export const MW_HEADER = 'x-camada-mw';
export const MW_WINDOW_MS = 30_000;   // middleware → route handler takes milliseconds; 30 s covers a cold function start
const MW_SKEW_MS = 5_000;             // the middleware's clock may run ahead of the function's (edge vs. Node on Vercel)

/** What the mark binds: when it was made, the method, the path and query, the rid, and the client chain as forwarded.
 *  JSON keeps the fields apart, since the rid and X-Forwarded-For are whatever the client sent where the middleware did not run. */
const markInput = (ts: number, req: Request, rid: string): string => {
  const url = new URL(req.url);
  return 'mw:' + JSON.stringify([ts, req.method, url.pathname + url.search, rid, req.headers.get('x-forwarded-for') ?? '']);
};

/** `<ms timestamp>.<HMAC-SHA256 hex>` under the server-only secret. */
export async function middlewareMark(secret: string, req: Request, rid: string, now = Date.now()): Promise<string> {
  return `${now}.${await hmacHex(secret, markInput(now, req, rid))}`;
}

/** True only for a mark this deployment's middleware made for this very request line and client, within the window.
 *  A copied pair fails on another path, query, method or client, and on any request once the window has passed. */
export async function middlewareMarkValid(secret: string, req: Request, now = Date.now()): Promise<boolean> {
  const m = /^(\d{13})\.([0-9a-f]{64})$/.exec(req.headers.get(MW_HEADER) ?? '');
  const rid = req.headers.get('x-camada-rid');
  if (!m || !rid) return false;
  const ts = Number(m[1]);
  if (now - ts > MW_WINDOW_MS || ts - now > MW_SKEW_MS) return false;
  return safeEqual(m[2], await hmacHex(secret, markInput(ts, req, rid)));
}

export const SESSION_COOKIE = '_sfp';   // the same session cookie as the edge collector and @camada/node: sid/ns comparable across taps

export const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

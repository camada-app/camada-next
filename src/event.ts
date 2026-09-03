// One wire-event builder for every @camada/next entry (middleware + beacon route). Web APIs
// only: this sits in the middleware's edge-safe import graph.
import { buildWireEvent, TAP_NEXT, type WireEvent } from '@camada/core';

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

export const SESSION_COOKIE = '_sfp';   // the same session cookie as the edge collector and @camada/node: sid/ns comparable across taps

export const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

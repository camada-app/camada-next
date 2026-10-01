// A waitUntil for code that runs inside a route handler or server action (withCamada, track()). A
// serverless host (Vercel) may freeze the function once the response has gone out, and the event's
// flush only starts then, when the body is done. Next's after() (15.1+) holds the function open
// until its callback settles, but it must be called inside the request scope, which the body-done
// callback is not. So the first promise handed in registers ONE after() callback; it runs once the
// response has closed and drains every promise handed in, including any that arrive while it waits.
// Without after() (Next 15.0, or outside a request scope) the host's request context waitUntil is
// used, the one @vercel/functions reads; with neither, the promise is left to run, which a
// long-lived `next start` process does anyway.
import * as nextServer from 'next/server';

type WaitUntil = (p: Promise<unknown>) => void;
type After = (task: () => Promise<unknown>) => void;
type RequestContext = { get?: () => { waitUntil?: WaitUntil } | undefined };

function contextWaitUntil(): WaitUntil | undefined {
  const g = globalThis as Record<symbol, RequestContext | undefined>;
  for (const name of ['@next/request-context', '@vercel/request-context']) {
    const ctx = g[Symbol.for(name)]?.get?.();
    if (typeof ctx?.waitUntil === 'function') return (p) => ctx.waitUntil!(p);
  }
  return undefined;
}

/** Call once per request, inside its scope; hand the result to everything that flushes for it. Never throws. */
export function requestWaitUntil(): WaitUntil {
  const pending: Promise<unknown>[] = [];
  let hold: WaitUntil | null | undefined;   // undefined = not decided yet; null = nothing to hold the host open with
  const drain = async () => {
    for (let i = 0; i < pending.length; i++) await pending[i].catch(() => {});
  };
  return (p) => {
    if (hold === undefined) {
      hold = null;
      try {
        const after = (nextServer as { after?: After }).after;
        if (typeof after !== 'function') throw new Error('no after()');
        after(drain);   // throws outside a request scope
        hold = (q) => { pending.push(q); };
      } catch {
        try { hold = contextWaitUntil() ?? null; } catch { hold = null; }
      }
    }
    try { hold?.(p); } catch { /* a host that refuses the promise costs only the hold */ }
  };
}

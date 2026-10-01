// track() — app-context outcome events recorded from a server action, route handler, or server
// component, joined to the middleware's wire event. The name is free-form; the analyst's rules read
// this vocabulary: login_failed, login_succeeded, signup, password_reset, mfa_failed, payment_failed,
// payment_succeeded, coupon_failed (@camada/node README has the table). Inside withCamada() an
// event joins on the wrapper's own rid and session; elsewhere on the x-camada-rid the middleware
// stamps and the _sfp session cookie. The identifier is
// HMAC-hashed in-process with the ingest token: the raw value never reaches the queue, and
// the analyst drops anything that is not hash-shaped anyway.
// next/headers is imported lazily inside the call (the beacon.tsx pattern) so this module
// stays importable everywhere; calling track() outside a request scope is a no-op.
import { hashUserId, logRateLimited, resolveClientIp, TAP_NEXT } from '@camada/core';
import { getEngine, isDisabled, trustedProxy } from './engine';
import { requestWaitUntil } from './wait-until';

const SESSION_COOKIE = '_sfp';

interface Scope { rid: string; sid: string | null }
interface Als { run<R>(store: Scope, fn: () => R): R; getStore(): Scope | undefined }
let als: Als | null | undefined;
/** Next puts AsyncLocalStorage on globalThis in both runtimes (node-environment-baseline, the edge sandbox). */
const scopes = (): Als | null => {
  if (als === undefined) {
    const Ctor = (globalThis as { AsyncLocalStorage?: new () => Als }).AsyncLocalStorage;
    als = Ctor ? new Ctor() : null;   // ponytail: without it (never under Next) a wrapped route's track() falls back to the header
  }
  return als;
};

/** withCamada() runs its handler here, so track() inside it takes the wrapper's rid and never a
 *  client-sent x-camada-rid: a wrapped route sits outside the matcher, where nothing strips it. */
export const withTrackScope = <R>(scope: Scope, fn: () => R): R => { const s = scopes(); return s ? s.run(scope, fn) : fn(); };

/** Never throws, never blocks the response: a camada problem must not break a login. */
export async function track(event: string, data?: { user?: string }): Promise<void> {
  try {
    if (isDisabled()) return;
    const engine = getEngine();
    if (!engine) return;
    const { headers, cookies } = await import('next/headers');
    const [h, c] = await Promise.all([headers(), cookies()]);
    const scope = scopes()?.getStore();
    const uid = data?.user ? await hashUserId(data.user, engine.env.ingestToken) : null;
    engine.queue.push({
      tap: TAP_NEXT,
      et: event,
      uid,
      rid: scope ? scope.rid : h.get('x-camada-rid'),
      sid: scope?.sid ?? c.get(SESSION_COOKIE)?.value ?? null,
      ip: resolveClientIp(null, h.get('x-forwarded-for'), trustedProxy(engine)),
      ts: Date.now(),
    });
    void engine.queue.flush(requestWaitUntil());   // a serverless runtime may freeze right after the response: hold it open for the flush
  } catch (err) {
    logRateLimited(err);   // outside a request scope, unconfigured, or a camada bug: swallow
  }
}

// track() — app-context outcome events recorded from a server action, route handler, or server
// component, joined to the middleware's wire event. The name is free-form; the analyst's rules read
// this vocabulary: login_failed, login_succeeded, signup, password_reset, mfa_failed, payment_failed,
// payment_succeeded, coupon_failed (@camada/node README has the table). Events are joined
// through the x-camada-rid request header and the _sfp session cookie. The identifier is
// HMAC-hashed in-process with the ingest token: the raw value never reaches the queue, and
// the analyst drops anything that is not hash-shaped anyway.
// next/headers is imported lazily inside the call (the beacon.tsx pattern) so this module
// stays importable everywhere; calling track() outside a request scope is a no-op.
import { hashUserId, logRateLimited, resolveClientIp, TAP_NEXT } from '@camada/core';
import { getEngine, isDisabled, trustedProxy } from './engine';

const SESSION_COOKIE = '_sfp';

/** Never throws, never blocks the response: a camada problem must not break a login. */
export async function track(event: string, data?: { user?: string }): Promise<void> {
  try {
    if (isDisabled()) return;
    const engine = getEngine();
    if (!engine) return;
    const { headers, cookies } = await import('next/headers');
    const [h, c] = await Promise.all([headers(), cookies()]);
    const uid = data?.user ? await hashUserId(data.user, engine.env.ingestToken) : null;
    engine.queue.push({
      tap: TAP_NEXT,
      et: event,
      uid,
      rid: h.get('x-camada-rid'),
      sid: c.get(SESSION_COOKIE)?.value ?? null,
      ip: resolveClientIp(null, h.get('x-forwarded-for'), trustedProxy(engine)),
      ts: Date.now(),
    });
    void engine.queue.flush();   // a serverless runtime may freeze right after the response; don't wait for the interval
  } catch (err) {
    logRateLimited(err);   // outside a request scope, unconfigured, or a camada bug: swallow
  }
}

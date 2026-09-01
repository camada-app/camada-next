import { describe, it, expect, vi, afterEach } from 'vitest';
import { fakeAnalyst, ENV } from './harness';
import { configure } from '../src/engine';
import { track } from '../src/track';

// Request-scope stand-ins for next/headers; the lazy dynamic import in track() resolves here.
const reqHeaders = new Map<string, string>();
const reqCookies = new Map<string, string>();
vi.mock('next/headers', () => ({
  headers: async () => ({ get: (k: string) => reqHeaders.get(k.toLowerCase()) ?? null }),
  cookies: async () => ({ get: (k: string) => (reqCookies.has(k) ? { name: k, value: reqCookies.get(k)! } : undefined) }),
}));

const settle = () => new Promise((r) => setTimeout(r, 30));

function setup(env: Record<string, string> = {}) {
  const a = fakeAnalyst();
  configure({ env: { ...ENV, ...env }, fetchImpl: a.fetchImpl });
  reqHeaders.clear(); reqCookies.clear();
  return a;
}

afterEach(() => configure({}));

describe('track', () => {
  it('ships an app-context event joined to the request rid/sid, uid hashed', async () => {
    const a = setup({ CAMADA_TRUSTED_PROXY: 'hops:1' });
    reqHeaders.set('x-camada-rid', 'rid-1');
    reqHeaders.set('x-forwarded-for', '198.51.100.7');
    reqCookies.set('_sfp', 'sid-1');
    await track('login_failed', { user: 'alice@example.com' });
    await settle();
    const [ev] = a.events.flat() as Array<Record<string, unknown>>;
    expect(ev).toMatchObject({ tap: 'sdk-next', et: 'login_failed', rid: 'rid-1', sid: 'sid-1', ip: '198.51.100.7' });
    expect(ev.uid).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(a.events)).not.toContain('alice@example.com');
  });

  it('ignores XFF without a trusted-proxy config (ip stays null at the edge)', async () => {
    const a = setup();
    reqHeaders.set('x-forwarded-for', '198.51.100.7');
    await track('signup');
    await settle();
    const [ev] = a.events.flat() as Array<Record<string, unknown>>;
    expect(ev.ip).toBeNull();
    expect(ev.uid).toBeNull();
  });

  it('is a no-op under the kill switch', async () => {
    const a = setup({ CAMADA_DISABLED: '1' });
    await track('login_failed', { user: 'alice@example.com' });
    await settle();
    expect(a.events).toHaveLength(0);
  });

  it('never throws unconfigured or with ingest down', async () => {
    const a = setup();
    a.ingestDown = true;
    await expect(track('login_failed', { user: 'x@y.z' })).resolves.toBeUndefined();
    configure({ env: {} });   // no CAMADA_KEY at all
    await expect(track('login_failed')).resolves.toBeUndefined();
  });
});

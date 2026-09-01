// Route handler suite (node environment — the handlers must run on both runtimes; the
// shared import graph is already proven node:-free by edge-safety.test.ts).
import { describe, it, expect, afterEach } from 'vitest';
import iife from '@camada/browser/iife-string';
import { camadaRoute } from '../src/route';
import { configure } from '../src/engine';
import { fakeAnalyst, ENV, BLOCKED_IP } from './harness';

afterEach(() => configure());

const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));
const url = (seg: string) => `https://app.example/api/camada/${seg}`;
const post = (seg: string, body: string, headers: Record<string, string> = {}) =>
  new Request(url(seg), { method: 'POST', body, headers, ...( { duplex: 'half' } as object ) });

describe('GET (beacon script)', () => {
  it('serves the IIFE at b.js', async () => {
    const a = fakeAnalyst();
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    const { GET } = camadaRoute();
    const res = await GET(new Request(url('b.js')));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('javascript');
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(await res.text()).toBe(iife);
  });

  it('404s when the tenant disabled the beacon', async () => {
    const a = fakeAnalyst();
    a.config.beacon = false;
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    const { GET } = camadaRoute();
    await GET(new Request(url('b.js')));   // kicks the lazy snapshot/config load
    await settle();
    const res = await GET(new Request(url('b.js')));
    expect(res.status).toBe(404);
  });

  it('404s on unknown segments and when unconfigured or disabled', async () => {
    const a = fakeAnalyst();
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    const { GET } = camadaRoute();
    expect((await GET(new Request(url('nope.js')))).status).toBe(404);
    configure({ env: {} });
    expect((await camadaRoute().GET(new Request(url('b.js')))).status).toBe(404);
    configure({ env: { ...ENV, CAMADA_DISABLED: '1' }, fetchImpl: a.fetchImpl });
    expect((await camadaRoute().GET(new Request(url('b.js')))).status).toBe(404);
  });
});

describe('POST (beacon relay)', () => {
  it('answers 204 and batches the beacon as a sig:1 row with the resolved ip and tap', async () => {
    const a = fakeAnalyst();
    configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl: a.fetchImpl });
    const { POST } = camadaRoute();
    const res = await POST(post('fp', JSON.stringify({ rid: 'abc', tz: 'UTC' }), { 'x-forwarded-for': '9.9.9.9' }));
    expect(res.status).toBe(204);
    expect(res.headers.get('cache-control')).toBe('no-store');
    await settle();
    expect(a.beacons).toHaveLength(0);   // no per-page-view POST /fp: it rides the /e batch
    const rows = a.events.flat() as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ sig: 1, rid: 'abc', tz: 'UTC', ip: '9.9.9.9', tap: 'sdk-next' });
  });

  it('drops an unparseable body instead of shipping it', async () => {
    const a = fakeAnalyst();
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    const res = await camadaRoute().POST(post('fp', 'not-json'));
    expect(res.status).toBe(204);
    await settle();
    expect(a.beacons).toHaveLength(0);
    expect(a.events.flat()).toHaveLength(0);
  });

  it('rejects oversized bodies with 413 and relays nothing', async () => {
    const a = fakeAnalyst();
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    const res = await camadaRoute().POST(post('fp', 'x'.repeat(80 * 1024)));
    expect(res.status).toBe(413);
    await settle();
    expect(a.beacons).toHaveLength(0);
  });

  it('404s on unknown segments; 204s inert when unconfigured', async () => {
    const a = fakeAnalyst();
    configure({ env: ENV, fetchImpl: a.fetchImpl });
    expect((await camadaRoute().POST(post('nope', '{}'))).status).toBe(404);
    configure({ env: {} });
    const res = await camadaRoute().POST(post('fp', '{}'));
    expect(res.status).toBe(204);
    await settle();
    expect(a.beacons).toHaveLength(0);
  });
});

describe('route-level enforcement (matcher-independent)', () => {
  it('403s a blocked client on the beacon endpoints even when middleware never ran', async () => {
    const a = fakeAnalyst();
    configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl: a.fetchImpl });
    const { GET, POST } = camadaRoute();
    // prime the lazy snapshot
    await GET(new Request('https://app.example/api/camada/b.js'));
    await new Promise((r) => setTimeout(r, 20));
    const g = await GET(new Request('https://app.example/api/camada/b.js', { headers: { 'x-forwarded-for': BLOCKED_IP } }));
    expect(g.status).toBe(403);
    expect(g.headers.get('x-block-reason')).toBe('ip4');
    const p = await POST(new Request('https://app.example/api/camada/fp', { method: 'POST', body: '{}', headers: { 'x-forwarded-for': BLOCKED_IP } }));
    expect(p.status).toBe(403);
  });
});

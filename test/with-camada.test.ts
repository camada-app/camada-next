// withCamada(): the route-handler position ships the real status and a dur covering the body,
// and steps aside when the middleware already shipped this request (no double count).
import { describe, it, expect, afterEach, vi } from 'vitest';
import { withCamada } from '../src/with-camada';
import { middlewareMark } from '../src/event';
import { configure } from '../src/engine';
import { fakeAnalyst, ENV, BLOCKED_IP, type FakeAnalyst } from './harness';

const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));
const env: Record<string, string> = { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' };

afterEach(() => { configure(); vi.unstubAllGlobals(); });

/** The fetch pipeline resolves the global fetch at call time: route it to the fake analyst. */
async function primed(): Promise<FakeAnalyst> {
  const a = fakeAnalyst();
  configure({ env, fetchImpl: a.fetchImpl });
  vi.stubGlobal('fetch', a.fetchImpl);
  await withCamada(() => new Response('warm'))(new Request('https://app.example/__prime'));   // cold: loads the snapshot
  await settle();
  a.events.length = 0;
  return a;
}

const evs = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

/** Three chunks 40 ms apart: a body that outlives the handler. */
const slowBody = (): ReadableStream<Uint8Array> => {
  let i = 0;
  return new ReadableStream({
    async pull(ctrl) {
      await new Promise((r) => setTimeout(r, 40));
      if (i++ < 3) ctrl.enqueue(new TextEncoder().encode('x')); else ctrl.close();
    },
  });
};

describe('withCamada', () => {
  it('ships one sdk-next event with st and a dur covering a streamed body, and mints the session', async () => {
    const a = await primed();
    const GET = withCamada(async (_req: Request, _ctx: { params: Promise<object> }) => new Response(slowBody(), { status: 201 }));
    const res = await GET(new Request('https://app.example/api/data', { headers: { 'x-forwarded-for': '8.8.8.8' } }), { params: Promise.resolve({}) });
    await settle();
    expect(evs(a)).toHaveLength(0);   // still streaming
    expect(await res.text()).toBe('xxx');
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ tap: 'sdk-next', p: '/api/data', st: 201, ip: '8.8.8.8', ns: 1 })]);
    expect(evs(a)[0].dur as number).toBeGreaterThanOrEqual(140);
    expect(res.headers.get('set-cookie')).toMatch(/^_sfp=/);
  });

  it('steps aside when the middleware already shipped this request, and not for a forged proof', async () => {
    const a = await primed();
    const GET = withCamada(() => new Response('ok'));
    const rid = crypto.randomUUID();
    const signed = await GET(new Request('https://app.example/api/data', { headers: { 'x-camada-rid': rid, 'x-camada-mw': await middlewareMark(env.CAMADA_KEY, rid) } }));
    expect(await signed.text()).toBe('ok');
    await settle();
    expect(evs(a)).toHaveLength(0);   // the middleware's pre-response event is the one record of it
    const forged = await GET(new Request('https://app.example/api/data', { headers: { 'x-camada-rid': rid, 'x-camada-mw': 'f'.repeat(64) } }));
    await forged.text();
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ p: '/api/data', st: 200 })]);
  });

  it('blocks before the handler runs, and reports the status a thrown redirect() answers with', async () => {
    const a = await primed();
    const handler = vi.fn(() => new Response('secret'));
    const blocked = await withCamada(handler)(new Request('https://app.example/api/data', { headers: { 'x-forwarded-for': BLOCKED_IP } }));
    expect(blocked.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    const redirect = withCamada(() => { throw Object.assign(new Error('NEXT_REDIRECT'), { digest: 'NEXT_REDIRECT;replace;/login;307;' }); });
    await expect(redirect(new Request('https://app.example/api/me'))).rejects.toThrow('NEXT_REDIRECT');
    await settle();
    expect(evs(a).find((e) => e.p === '/api/me')).toMatchObject({ st: 307 });
  });

  it('is inert without a key', async () => {
    configure({ env: {} });
    const res = await withCamada(() => new Response('plain'))(new Request('https://app.example/api/data'));
    expect(await res.text()).toBe('plain');
    expect(res.headers.get('set-cookie')).toBeNull();
  });
});

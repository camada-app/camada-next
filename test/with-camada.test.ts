// withCamada(): the route-handler position ships the real status and a dur covering the body,
// enforces on every request whatever headers it carries, and skips only its event when the
// middleware's mark proves the middleware already shipped this very request (no double count).
import { describe, it, expect, afterEach, vi } from 'vitest';
import { AsyncLocalStorage } from 'node:async_hooks';
import { NextRequest } from 'next/server';
import { withCamada } from '../src/with-camada';
import { track } from '../src/track';
import { camada } from '../src/middleware';
import { middlewareMark, MW_WINDOW_MS } from '../src/event';
import { configure } from '../src/engine';
import { fakeAnalyst, fakeEvent, ENV, BLOCKED_IP, type FakeAnalyst } from './harness';

// next/server's after(): a stand-in that records the callbacks, or throws as it does outside a request scope.
let afterImpl: ((task: () => Promise<unknown>) => void) | null = null;
vi.mock('next/server', async (importOriginal) => ({
  ...(await importOriginal<typeof import('next/server')>()),
  after: (task: () => Promise<unknown>) => {
    if (!afterImpl) throw new Error('`after` was called outside a request scope');
    afterImpl(task);
  },
}));

// next/headers for track(): the request headers the route was called with.
let reqHeaders = new Headers();
vi.mock('next/headers', () => ({
  headers: async () => reqHeaders,
  cookies: async () => ({ get: () => undefined }),
}));
// Next puts AsyncLocalStorage on globalThis in both runtimes; vitest does not.
(globalThis as { AsyncLocalStorage?: unknown }).AsyncLocalStorage = AsyncLocalStorage;

const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));
const env: Record<string, string> = { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' };

afterEach(() => { configure(); vi.unstubAllGlobals(); afterImpl = null; });

/** The fetch pipeline resolves the global fetch at call time: route it to the fake analyst. */
async function primed(fetchImpl?: typeof fetch): Promise<FakeAnalyst> {
  const a = fakeAnalyst();
  configure({ env, fetchImpl: a.fetchImpl });
  vi.stubGlobal('fetch', fetchImpl ?? a.fetchImpl);
  await withCamada(() => new Response('warm'))(new Request('https://app.example/__prime'));   // cold: loads the snapshot
  await settle();
  a.events.length = 0;
  return a;
}
const evs = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

/** Three chunks 40 ms apart: a body that outlives the handler. Sent as an event stream, the kind core times to its last byte. */
const SSE = { 'content-type': 'text/event-stream' };
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
    const GET = withCamada(async (_req: Request, _ctx: { params: Promise<object> }) => new Response(slowBody(), { status: 201, headers: SSE }));
    const res = await GET(new Request('https://app.example/api/data', { headers: { 'x-forwarded-for': '8.8.8.8' } }), { params: Promise.resolve({}) });
    await settle();
    expect(evs(a)).toHaveLength(0);   // still streaming
    expect(await res.text()).toBe('xxx');
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ tap: 'sdk-next', p: '/api/data', st: 201, ip: '8.8.8.8', ns: 1 })]);
    expect(evs(a)[0].dur as number).toBeGreaterThanOrEqual(140);
    expect(res.headers.get('set-cookie')).toMatch(/^_sfp=/);
  });

  /** A request as the middleware forwards it to the route: its own rid and a mark made now (or at `ts`). */
  async function marked(url: string, init: { method?: string; xff?: string; ts?: number } = {}, sentAs?: { url?: string; method?: string; xff?: string }) {
    const rid = crypto.randomUUID();
    const headers = (xff?: string): Record<string, string> => (xff ? { 'x-forwarded-for': xff } : {});
    const made = new Request(url, { method: init.method, headers: headers(init.xff) });
    const mark = await middlewareMark(env.CAMADA_KEY, made, rid, init.ts);
    const xff = sentAs?.xff ?? init.xff;
    return new Request(sentAs?.url ?? url, { method: sentAs?.method ?? init.method, headers: { ...headers(xff), 'x-camada-rid': rid, 'x-camada-mw': mark } });
  }

  it('skips its event when the middleware already shipped this request, and not for a forged mark', async () => {
    const a = await primed();
    const GET = withCamada(() => new Response('ok'));
    const signed = await GET(await marked('https://app.example/api/data?x=1', { xff: '8.8.8.8' }));
    expect(await signed.text()).toBe('ok');
    expect(signed.headers.get('set-cookie')).toBeNull();   // the middleware's _sfp is the session
    await settle();
    expect(evs(a)).toHaveLength(0);   // the middleware's pre-response event is the one record of it
    const rid = crypto.randomUUID();
    for (const forged of [`${Date.now()}.${'f'.repeat(64)}`, 'f'.repeat(64), '']) {
      await (await GET(new Request('https://app.example/api/data', { headers: { 'x-camada-rid': rid, 'x-camada-mw': forged } }))).text();
    }
    await settle();
    expect(evs(a)).toEqual([0, 1, 2].map(() => expect.objectContaining({ p: '/api/data', st: 200 })));
  });

  it("track() inside a wrapped route joins on the wrapper's rid, never a client-sent x-camada-rid", async () => {
    const a = await primed();
    const POST = withCamada(async (req: Request) => { reqHeaders = req.headers; await track('login_failed'); return new Response('no', { status: 401 }); });
    await (await POST(new Request('https://app.example/api/login', { method: 'POST', headers: { 'x-camada-rid': 'forged' } }))).text();
    await settle();
    const wire = evs(a).find((e) => e.p === '/api/login')!;
    const et = evs(a).find((e) => e.et === 'login_failed')!;
    expect(et.rid).not.toBe('forged');
    expect(et.rid).toBe(wire.rid);
    expect(et.sid).toBe(wire.sid);   // the session the wrapper just minted
    // the middleware matched too: its stamped, proven rid is the request's, and track() keeps it
    a.events.length = 0;
    const signed = await marked('https://app.example/api/login', { method: 'POST' });
    await (await POST(signed)).text();
    await settle();
    expect(evs(a).find((e) => e.et === 'login_failed')!.rid).toBe(signed.headers.get('x-camada-rid'));
  });

  it('never lets a mark skip enforcement: a blocked client with a valid mark is still blocked', async () => {
    const a = await primed();
    const handler = vi.fn(() => new Response('secret'));
    const res = await withCamada(handler)(await marked('https://app.example/api/data', { xff: BLOCKED_IP }));
    expect(res.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ p: '/api/data', st: 403, blk: 'ip4' })]);
  });

  it('a replayed mark does not verify from another client, after the window, on another path, query or method', async () => {
    const a = await primed();
    const handler = withCamada(() => new Response('ok'));
    const url = 'https://app.example/api/data';
    const replays = [
      await marked(url, { xff: '8.8.8.8' }, { xff: '9.9.9.9' }),                          // another client ip
      await marked(url, { xff: '8.8.8.8' }, { xff: '1.1.1.1, 8.8.8.8' }),                // the same ip behind another chain
      await marked(url, { ts: Date.now() - MW_WINDOW_MS - 1_000 }),                      // past the window
      await marked(url, { ts: Date.now() + 60_000 }),                                    // minted in the future
      await marked(url, {}, { url: 'https://app.example/api/other' }),                   // another path
      await marked(url, {}, { url: 'https://app.example/api/data?id=2' }),               // another query
      await marked(url, {}, { method: 'POST' }),                                         // another method
    ];
    for (const r of replays) {
      const res = await handler(r);
      expect(res.status).toBe(200);
      await res.text();   // the event ships once the body has gone out
    }
    await settle();
    expect(evs(a)).toHaveLength(replays.length);   // full enforcement and an event for every one
    expect(evs(a).every((e) => e.st === 200 && typeof e.dur === 'number')).toBe(true);
  });

  it('middleware then wrapper: one request, one event, whether or not the middleware matched', async () => {
    const a = await primed();
    const mw = camada();
    const route = withCamada(() => new Response('ok'));
    // What Next does with NextResponse.next({ request: { headers } }): the route sees the overridden request headers.
    const throughMiddleware = async (url: string, headers: Record<string, string>) => {
      const ev = fakeEvent();
      const res = await mw(new NextRequest(url, { headers }), ev as never);
      await ev.settled();
      const names = res?.headers.get('x-middleware-override-headers')?.split(',') ?? [];
      const forwarded = Object.fromEntries(names.map((n) => [n, res!.headers.get(`x-middleware-request-${n}`) ?? '']));
      const out = await route(new Request(url, { headers: names.length ? forwarded : headers }));
      return { mwRid: res?.headers.get('x-rid'), out };
    };
    const { mwRid, out } = await throughMiddleware('https://app.example/api/data', { 'x-forwarded-for': '8.8.8.8' });
    await out.text();
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ p: '/api/data', st: null, rid: mwRid })]);   // the middleware's, and its x-rid
    expect(out.headers.get('x-rid')).toBeNull();   // Next merges the middleware's x-rid onto the route's response: no second one
    a.events.length = 0;
    // a client mark is stripped by the middleware, and this one forges nothing on an unmatched route either
    await (await route(new Request('https://app.example/api/data', { headers: { 'x-forwarded-for': '8.8.8.8' } }))).text();
    await settle();
    expect(evs(a)).toEqual([expect.objectContaining({ p: '/api/data', st: 200 })]);   // the wrapper's
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

  it('holds a serverless function open with after() until the event has flushed', async () => {
    let open = () => {};
    const gate = new Promise<void>((r) => { open = r; });
    const a0 = fakeAnalyst();
    const gated = (async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith('/e')) await gate;
      return a0.fetchImpl(url, init);
    }) as typeof fetch;
    const a = await primed(gated);
    a.events = a0.events;
    const tasks: Array<() => Promise<unknown>> = [];
    afterImpl = (task) => tasks.push(task);
    const res = await withCamada(() => new Response(slowBody(), { headers: SSE }))(new Request('https://app.example/api/data'));
    expect(tasks).toHaveLength(1);   // one after() per request, registered inside its scope
    await res.text();   // the response has closed: Next runs the after() callbacks now
    let drained = false;
    const done = tasks[0]().then(() => { drained = true; });
    await settle();
    expect(drained).toBe(false);   // the flush is still in flight: the function must stay up
    open();
    await done;
    expect(evs(a).filter((e) => e.p === '/api/data')).toEqual([expect.objectContaining({ p: '/api/data', st: 200 })]);   // primed()'s /__prime event also flushes through the gate
  });

  it('falls back to the request context waitUntil where after() is unavailable', async () => {
    const a = await primed();
    const held: Promise<unknown>[] = [];
    const sym = Symbol.for('@vercel/request-context');
    (globalThis as Record<symbol, unknown>)[sym] = { get: () => ({ waitUntil: (p: Promise<unknown>) => held.push(p) }) };
    try {
      const res = await withCamada(() => new Response('ok'))(new Request('https://app.example/api/data'));
      await res.text();
      expect(held.length).toBeGreaterThan(0);
      await Promise.all(held);
      expect(evs(a)).toEqual([expect.objectContaining({ p: '/api/data', st: 200 })]);
    } finally {
      delete (globalThis as Record<symbol, unknown>)[sym];
    }
  });

  it("stamps x-rid with the rid of the row it ships, on a mutable response and on an immutable one alike", async () => {
    const a = await primed();
    const plain = await withCamada(() => new Response('ok', { headers: { 'x-app': '1' } }))(new Request('https://app.example/api/data'));
    expect(await plain.text()).toBe('ok');
    expect(plain.headers.get('x-app')).toBe('1');
    // Response.redirect() and a fetch() result have immutable headers: a copy carries them, status and body unchanged
    const redirect = await withCamada(() => Response.redirect('https://app.example/login', 307))(new Request('https://app.example/api/me'));
    expect(redirect.status).toBe(307);
    expect(redirect.headers.get('location')).toBe('https://app.example/login');
    expect(redirect.headers.get('set-cookie')).toMatch(/^_sfp=/);
    await settle();
    const rid = (p: string) => evs(a).find((e) => e.p === p)!.rid;
    expect(plain.headers.get('x-rid')).toBe(rid('/api/data'));
    expect(redirect.headers.get('x-rid')).toBe(rid('/api/me'));
    // a streamed body keeps it through core's re-wrap
    const sse = await withCamada(() => new Response(slowBody(), { headers: SSE }))(new Request('https://app.example/api/stream'));
    await sse.text();
    await settle();
    expect(sse.headers.get('x-rid')).toBe(rid('/api/stream'));
  });

  it('leaves x-rid to the middleware on a request it shipped, and never touches a 101', async () => {
    await primed();
    const signed = await withCamada(() => new Response('ok'))(await marked('https://app.example/api/data'));
    expect(signed.headers.get('x-rid')).toBeNull();   // the middleware's response carries its own, that row's rid
    // undici refuses to construct a 101; a websocket upgrade's response looks like this to the wrapper
    const upgrade = { status: 101, headers: new Headers({ upgrade: 'websocket' }), body: null } as unknown as Response;
    const res = await withCamada(() => upgrade)(new Request('https://app.example/ws'));
    expect(res.headers.get('x-rid')).toBeNull();
  });

  it('is inert without a key', async () => {
    configure({ env: {} });
    const res = await withCamada(() => new Response('plain'))(new Request('https://app.example/api/data'));
    expect(await res.text()).toBe('plain');
    expect(res.headers.get('set-cookie')).toBeNull();
  });
});

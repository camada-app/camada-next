// @vitest-environment edge-runtime
// The middleware behavior suite runs with @edge-runtime/vm globals (Vercel's edge runtime
// primitives). The bundle-level proof that no node: import can sneak into this entry's
// import graph lives in test/edge-safety.test.ts.
import { describe, it, expect, afterEach } from 'vitest';
import { NextRequest, type NextFetchEvent } from 'next/server';
import { camada } from '../src/middleware';
import { configure, getEngine } from '../src/engine';
import { fakeAnalyst, fakeEvent, ENV, BLOCKED_IP, type FakeAnalyst } from './harness';

afterEach(() => configure());   // reset the singleton, stop queue timers

type Ev = ReturnType<typeof fakeEvent>;
const asEvent = (ev: Ev) => ev as unknown as NextFetchEvent;

function mw(a: FakeAnalyst, env: Record<string, string | undefined> = {}) {
  configure({ env: { ...ENV, ...env }, fetchImpl: a.fetchImpl });
  return camada();
}

function req(path: string, headers: Record<string, string> = {}) {
  return new NextRequest(`https://app.example${path}`, { headers });
}

/** First request kicks the lazy snapshot load (cold, fails open); await it, drop its event. */
async function primed(a: FakeAnalyst, env: Record<string, string | undefined> = {}) {
  const handler = mw(a, env);
  const ev = fakeEvent();
  handler(req('/__prime'), asEvent(ev));
  await ev.settled();
  a.events.length = 0;
  return handler;
}

describe('inline blocking', () => {
  it('answers 403 with block headers and ships the event with st 403', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    const ev = fakeEvent();
    const res = handler(req('/', { 'x-forwarded-for': BLOCKED_IP }), asEvent(ev));
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-reason')).toBe('ip4');
    expect(res?.headers.get('x-block-version')).toBeTruthy();
    await ev.settled();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(1);
    expect(evs[0].st).toBe(403);
    expect(evs[0].ip).toBe(BLOCKED_IP);
    expect(evs[0].tap).toBe('sdk-next');
  });

  it('ignores a spoofed XFF without trusted-proxy config', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);   // no CAMADA_TRUSTED_PROXY, server config mode none
    const res = handler(req('/', { 'x-forwarded-for': BLOCKED_IP }), asEvent(fakeEvent()));
    expect(res?.status).not.toBe(403);
  });

  it('fails open while cold (snapshot server down)', async () => {
    const a = fakeAnalyst();
    a.snapshotDown = true;
    const handler = mw(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    const ev = fakeEvent();
    const res = handler(req('/', { 'x-forwarded-for': BLOCKED_IP }), asEvent(ev));
    expect(res?.status).not.toBe(403);           // Next continues: fail open
    expect(res?.headers.get('x-rid')).toBeTruthy();
    await ev.settled();                          // load + flush promises must not reject
  });
});

describe('request capture', () => {
  it('miss: NextResponse.next with x-camada-rid on the request and x-rid on the response', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);
    const ev = fakeEvent();
    const res = handler(req('/pricing?ref=x', { accept: 'text/html' }), asEvent(ev));
    const rid = res?.headers.get('x-rid');
    expect(rid).toMatch(/^[0-9a-f-]{36}$/);
    // NextResponse.next({request}) encodes the forwarded request headers onto the response:
    expect(res?.headers.get('x-middleware-request-x-camada-rid')).toBe(rid);
    await ev.settled();
    const e = (a.events.flat() as Array<Record<string, unknown>>)[0];
    expect(e.rid).toBe(rid);
    expect(e.tap).toBe('sdk-next');
    expect(e.p).toBe('/pricing');
    expect(e.q).toBe('?ref=x');
    expect(e.st).toBeNull();                     // ships pre-response, like the edge collector
    expect(String(e.hord)).toContain('accept');  // sorted by the edge runtime, still shipped
  });

  it('passes x-vercel-ja4-digest through as ja4', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);
    const ev = fakeEvent();
    handler(req('/', { 'x-vercel-ja4-digest': 'ja4_deadbeef' }), asEvent(ev));
    await ev.settled();
    const e = (a.events.flat() as Array<Record<string, unknown>>)[0];
    expect(e.ja4).toBe('ja4_deadbeef');
  });

  it('honors config exclude', async () => {
    const a = fakeAnalyst();
    a.config.exclude = ['/static/'];
    const handler = await primed(a);
    const ev = fakeEvent();
    handler(req('/static/app.css'), asEvent(ev));
    handler(req('/page'), asEvent(ev));
    await ev.settled();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(1);
    expect(evs[0].p).toBe('/page');
  });

  it('hands its background work to event.waitUntil', async () => {
    const a = fakeAnalyst();
    const handler = mw(a);
    const ev = fakeEvent();
    handler(req('/'), asEvent(ev));
    expect(ev.promises.length).toBeGreaterThan(0);   // snapshot load and/or queue flush
    await ev.settled();
  });
});

describe('fail-open envelope', () => {
  it('CAMADA_DISABLED=1 returns undefined (checked per request)', async () => {
    const a = fakeAnalyst();
    const handler = mw(a, { CAMADA_DISABLED: '1', CAMADA_TRUSTED_PROXY: 'hops:1' });
    const res = handler(req('/', { 'x-forwarded-for': BLOCKED_IP }), asEvent(fakeEvent()));
    expect(res).toBeUndefined();
  });

  it('unconfigured returns undefined instead of crashing', async () => {
    const a = fakeAnalyst();
    configure({ env: {}, fetchImpl: a.fetchImpl });
    const handler = camada();
    const res = handler(req('/'), asEvent(fakeEvent()));
    expect(res).toBeUndefined();
    expect(getEngine()).toBeNull();
  });

  it('keeps serving when ingest is down', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);
    a.ingestDown = true;
    const ev = fakeEvent();
    const res = handler(req('/'), asEvent(ev));
    expect(res?.headers.get('x-rid')).toBeTruthy();
    await ev.settled();                          // flush swallows the failure
  });
});

describe('session cookie (_sfp, same as the collector and @camada/node)', () => {
  it('sets the cookie on a fresh visitor and marks the event as a new session', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);
    const ev = fakeEvent();
    const res = handler(req('/'), asEvent(ev))!;
    await ev.settled();
    const cookie = res.headers.get('set-cookie') || '';
    expect(cookie).toContain('_sfp=');
    expect(cookie).toContain('Secure');   // https request URL
    const sent = a.events.flat()[0] as Record<string, unknown>;
    expect(sent.ns).toBe(1);
    expect(sent.sid).toBeTruthy();
  });

  it('keeps an existing sid and does not reset the cookie', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a);
    const ev = fakeEvent();
    const res = handler(req('/', { cookie: '_sfp=known-sid; other=1' }), asEvent(ev))!;
    await ev.settled();
    expect(res.headers.get('set-cookie')).toBeNull();
    const sent = a.events.flat()[0] as Record<string, unknown>;
    expect(sent.sid).toBe('known-sid');
    expect(sent.ns).toBe(0);
  });
});

// @vitest-environment edge-runtime
// SDK-04 for @camada/next, under the edge-runtime globals the middleware really runs on:
// the middleware serves the proof-of-work page, camadaRoute()'s POST verifies the solution and
// sets `_cch`, and the cookie lets the next request through. The proof of work is solved here
// with the same WebCrypto the page's inline solver reproduces in a browser.
import { describe, it, expect, afterEach } from 'vitest';
import { NextRequest, type NextFetchEvent } from 'next/server';
import { CHALLENGE_COOKIE } from '@camada/core';
import { camada } from '../src/middleware';
import { camadaRoute } from '../src/route';
import { challengeGate } from '../src/challenge';
import { configure } from '../src/engine';
import { fakeAnalyst, fakeEvent, ENV, BLOCKED_IP, CHALLENGED_IP, ALLOWED_IP, type FakeAnalyst } from './harness';

afterEach(() => configure());

type Ev = ReturnType<typeof fakeEvent>;
const asEvent = (ev: Ev) => ev as unknown as NextFetchEvent;
const HTML = { accept: 'text/html', 'sec-fetch-dest': 'document' };

const req = (path: string, headers: Record<string, string> = {}, init: RequestInit = {}) =>
  new NextRequest(`https://app.example${path}`, { headers, ...init } as ConstructorParameters<typeof NextRequest>[1]);

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
async function solve(nonce: string): Promise<string> {
  const enc = new TextEncoder();
  for (let n = 0; ; n++) {
    if (hex(await crypto.subtle.digest('SHA-256', enc.encode(`${nonce}.${n}`))).startsWith('0000')) return String(n);
  }
}
const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];

/** A v4-serving analyst with the snapshot already loaded (the first call is cold). */
async function primed(env: Record<string, string | undefined> = {}, opts: Record<string, unknown> = {}) {
  const a = fakeAnalyst();
  a.v4 = true;
  configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1', ...env }, fetchImpl: a.fetchImpl, ...opts });
  const handler = camada();
  const ev = fakeEvent();
  await handler(req('/__prime'), asEvent(ev));
  await ev.settled();
  a.events.length = 0;
  return { a, handler };
}

const events = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

const verify = (body: string, headers: Record<string, string> = {}) =>
  camadaRoute().POST(new Request('https://app.example/api/camada/challenge', {
    method: 'POST',
    headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
  }));

/** Serves the page for `path`, solves it, and returns the verify Response. */
async function pass(handler: Awaited<ReturnType<typeof primed>>['handler'], path = '/cart') {
  const ev = fakeEvent();
  const page = await handler(req(path, { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(ev));
  const nonce = nonceOf(await page!.text());
  return verify(`nonce=${nonce}&solution=${await solve(nonce)}&to=${encodeURIComponent(path)}`);
}

describe('serving the challenge', () => {
  it('answers 403 with the proof-of-work page and ships blk: challenge', async () => {
    const { a, handler } = await primed();
    const ev = fakeEvent();
    const res = await handler(req('/cart?ref=x', { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(ev));
    expect(res!.status).toBe(403);
    expect(res!.headers.get('content-type')).toContain('text/html');
    expect(res!.headers.get('cache-control')).toBe('no-store');
    expect(res!.headers.get('x-camada-challenge')).toBe('1');
    const body = await res!.text();
    expect(body).toContain('Checking your browser');
    expect(body).toContain('value="/cart?ref=x"');
    await ev.settled();
    expect(events(a).at(-1)).toMatchObject({ st: 403, blk: 'challenge', tap: 'sdk-next' });
  });

  it('answers 403 JSON for a non-HTML request', async () => {
    const { handler } = await primed();
    const res = await handler(req('/checkout', { accept: 'application/json', 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    expect(res!.status).toBe(403);
    expect(await res!.json()).toEqual({ error: 'challenge_required' });
  });

  it('challenges on a path rule, not just an ip', async () => {
    const { handler } = await primed();
    const res = await handler(req('/admin/users', { ...HTML, 'x-forwarded-for': '8.8.8.8' }), asEvent(fakeEvent()));
    expect(res!.status).toBe(403);
    expect(res!.headers.get('x-camada-challenge')).toBe('1');
  });

  it('blocks outright rather than challenging when the ip is on the block side', async () => {
    const { handler } = await primed();
    const res = await handler(req('/', { ...HTML, 'x-forwarded-for': BLOCKED_IP }), asEvent(fakeEvent()));
    expect(res!.status).toBe(403);
    expect(res!.headers.get('x-block-reason')).toBe('ip4');
    expect(res!.headers.get('x-camada-challenge')).toBeNull();
  });

  it('honours the v4 allow side over a wider block', async () => {
    const { handler } = await primed();
    const res = await handler(req('/', { ...HTML, 'x-forwarded-for': ALLOWED_IP }), asEvent(fakeEvent()));
    expect(res?.status).not.toBe(403);
  });

  it('never challenges its own verify route', async () => {
    const { handler } = await primed();
    const res = await handler(req('/api/camada/challenge', { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    expect(res?.status).not.toBe(403);
  });

  it('asks the server for the v4 snapshot', async () => {
    const { a } = await primed();
    expect(a.snapshotVersions[0]).toBe('4');
  });

  it('does nothing when challenge is off', async () => {
    const { handler } = await primed({ CAMADA_CHALLENGE: '0' });
    const res = await handler(req('/cart', { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    expect(res?.status).not.toBe(403);
  });
});

describe('verifying the challenge', () => {
  it('sets _cch, redirects back, and ships st 200 + ch 1', async () => {
    const { a, handler } = await primed();
    const res = await pass(handler);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/cart');
    expect(res.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(res.headers.get('set-cookie')).toContain('HttpOnly');
    expect(events(a).at(-1)).toMatchObject({ st: 200, ch: 1, tap: 'sdk-next' });
  });

  it('lets the holder of a valid _cch through', async () => {
    const { handler } = await primed();
    const cookie = (await pass(handler)).headers.get('set-cookie')!.split(';')[0];
    const res = await handler(req('/cart', { ...HTML, cookie, 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    expect(res?.status).not.toBe(403);
  });

  it('does not accept a cookie minted for another ip', async () => {
    const { handler } = await primed();
    const cookie = (await pass(handler)).headers.get('set-cookie')!.split(';')[0];
    const res = await handler(req('/checkout', { ...HTML, cookie, 'x-forwarded-for': '203.0.114.55' }), asEvent(fakeEvent()));
    expect(res!.status).toBe(403);
  });

  it('re-serves the page on a wrong solution and sets no cookie', async () => {
    const { handler } = await primed();
    const page = await handler(req('/cart', { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    const nonce = nonceOf(await page!.text());
    const res = await verify(`nonce=${nonce}&solution=1&to=%2Fcart`);
    expect(res.status).toBe(403);
    expect(res.headers.get('set-cookie')).toBeNull();
  });

  it('rejects a forged nonce even with a valid proof of work', async () => {
    await primed();
    const forged = 'a'.repeat(32);
    const res = await verify(`nonce=${forged}&solution=${await solve(forged)}&to=%2Fcart`);
    expect(res.status).toBe(403);
    expect(res.headers.get('set-cookie')).toBeNull();
  });

  it('never redirects off-site', async () => {
    const { handler } = await primed();
    const page = await handler(req('/cart', { ...HTML, 'x-forwarded-for': CHALLENGED_IP }), asEvent(fakeEvent()));
    const nonce = nonceOf(await page!.text());
    const res = await verify(`nonce=${nonce}&solution=${await solve(nonce)}&to=${encodeURIComponent('https://evil.test')}`);
    expect(res.headers.get('location')).toBe('/');
  });

  it('still blocks a blocked ip at the verify endpoint', async () => {
    await primed();
    const res = await verify('nonce=x&solution=1&to=%2F', { 'x-forwarded-for': BLOCKED_IP });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
  });
});

describe('challengeGate()', () => {
  it('gates a route on demand and steps aside once passed', async () => {
    const { handler } = await primed();
    const gate = await challengeGate(new Request('https://app.example/challenge-me', { headers: { ...HTML, 'x-forwarded-for': '8.8.8.8' } }));
    expect(gate!.status).toBe(403);
    const nonce = nonceOf(await gate!.text());
    const ok = await camadaRoute().POST(new Request('https://app.example/api/camada/challenge', {
      method: 'POST',
      headers: { 'x-forwarded-for': '8.8.8.8', 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${await solve(nonce)}&to=%2Fchallenge-me`,
    }));
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const again = await challengeGate(new Request('https://app.example/challenge-me', { headers: { ...HTML, cookie, 'x-forwarded-for': '8.8.8.8' } }));
    expect(again).toBeNull();
    void handler;
  });
});

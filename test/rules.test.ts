// @vitest-environment edge-runtime
// Snapshot v5 (§D3): the tenant's ordered custom rules, enforced at the next middleware
// position over the golden v5 container edge-analyst generates. The order IS the precedence,
// so a skip rule above a wider block wins — and the axes this tap really has (path, user agent
// and the request headers) must reach the matcher, or every `ua` and `header` rule silently
// never fires.
import { describe, it, expect, afterEach } from 'vitest';
import { NextRequest, type NextFetchEvent } from 'next/server';
import { camada } from '../src/middleware';
import { configure } from '../src/engine';
import {
  fakeAnalyst, fakeEvent, ENV,
  BLOCKED_IP, ALLOWED_IP, RULE_BLOCKED_IP, SKIP_PATH, RULE_BLOCKED_PATH, WARN_UA, BLOCKED_UA,
  BLOCKED_HEADER, BLOCKED_HEADER_VALUE,
  type FakeAnalyst,
} from './harness';

afterEach(() => configure());   // reset the singleton, stop queue timers

type Ev = ReturnType<typeof fakeEvent>;
const asEvent = (ev: Ev) => ev as unknown as NextFetchEvent;

const req = (path: string, headers: Record<string, string> = {}) =>
  new NextRequest(`https://app.example${path}`, { headers });

/** A v5-serving analyst with the snapshot already loaded (the first call is cold). */
async function primed(opts: Record<string, unknown> = {}) {
  const a = fakeAnalyst();
  a.v5 = true;
  configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl: a.fetchImpl, ...opts });
  const handler = camada();
  const ev = fakeEvent();
  await handler(req('/__prime'), asEvent(ev));
  await ev.settled();
  a.events.length = 0;
  return { a, handler };
}

const events = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

/** One request through the middleware, with its waitUntil work settled. */
async function call(handler: ReturnType<typeof camada>, path: string, headers: Record<string, string>) {
  const ev = fakeEvent();
  const res = await handler(req(path, headers), asEvent(ev));
  await ev.settled();
  return res;
}

describe('ordered custom rules', () => {
  it('lets a skip rule beat the wider block below it', async () => {
    const { handler } = await primed();
    const skipped = await call(handler, SKIP_PATH, { 'x-forwarded-for': BLOCKED_IP });
    expect(skipped?.status).not.toBe(403);
    const blocked = await call(handler, '/', { 'x-forwarded-for': BLOCKED_IP });
    expect(blocked?.status).toBe(403);
  });

  it('lets the built-in Allow-list rule beat the wider block below it', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': ALLOWED_IP });
    expect(res?.status).not.toBe(403);
    expect(events(a).at(-1)!.wrn).toBeUndefined();   // an allowed request is an ordinary request
  });

  it('blocks by rule with x-block-rule and ships blk rule + rl', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': RULE_BLOCKED_IP });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-reason')).toBe('rule');
    expect(res?.headers.get('x-block-rule')).toBe('builtin:block');
    expect(res?.headers.get('x-block-version')).toBeTruthy();
    const evs = events(a);
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ st: 403, blk: 'rule', rl: 'builtin:block', ip: RULE_BLOCKED_IP });
  });

  it('blocks by a path rule the block side does not carry', async () => {
    const { handler } = await primed();
    const res = await call(handler, RULE_BLOCKED_PATH, { 'x-forwarded-for': '8.8.8.8' });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-rule')).toBe('cr_00000000000c');
  });

  it('blocks by a user-agent rule — the tap must pass ua through', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8', 'user-agent': BLOCKED_UA });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-rule')).toBe('cr_00000000000f');
    expect(events(a)[0]).toMatchObject({ blk: 'rule', rl: 'cr_00000000000f' });
  });

  it('blocks by a header rule — the tap must pass a header getter through', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8', [BLOCKED_HEADER]: BLOCKED_HEADER_VALUE });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-reason')).toBe('rule');
    expect(res?.headers.get('x-block-rule')).toBe('cr_000000000019');
    expect(events(a)[0]).toMatchObject({ blk: 'rule', rl: 'cr_000000000019' });
  });

  it('matches a header rule however the client spelled the name', async () => {
    const { handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8', 'X-API-Key': BLOCKED_HEADER_VALUE });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-rule')).toBe('cr_000000000019');
  });

  it('passes when the header the rule reads is absent', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8' });
    expect(res?.status).not.toBe(403);   // a condition the request cannot answer is false, negatives included
    const ev = events(a).at(-1)!;
    expect(ev.blk).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });

  it('passes a warn rule and stamps wrn on the event', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8', 'user-agent': WARN_UA });
    expect(res?.status).not.toBe(403);
    const ev = events(a).at(-1)!;
    expect(ev.wrn).toBe('cr_00000000000e');
    expect(ev.blk).toBeUndefined();   // warn is not a block: the traffic passed
  });

  it('leaves an unmatched request alone', async () => {
    const { a, handler } = await primed();
    const res = await call(handler, '/', { 'x-forwarded-for': '8.8.8.8', 'user-agent': 'Mozilla/5.0' });
    expect(res?.status).not.toBe(403);
    const ev = events(a).at(-1)!;
    expect(ev.wrn).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });
});

describe('snapshot negotiation', () => {
  it('asks for v5 by default', async () => {
    const { a } = await primed();
    expect(a.snapshotVersions[0]).toBe('5');
  });

  it('opts out of the rules entirely with snapshotVersion: 3', async () => {
    const { a } = await primed({ snapshotVersion: 3 });
    expect(a.snapshotVersions[0]).toBe('');   // no header at all: the v3 body is the default answer
  });

  it('still enforces against an analyst that only publishes v3', async () => {
    const a = fakeAnalyst();   // v3 container, while the client asks for 5 — §D3's fallback
    configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl: a.fetchImpl });
    const handler = camada();
    const prime = fakeEvent();
    await handler(req('/__prime'), asEvent(prime));
    await prime.settled();
    expect(a.snapshotVersions[0]).toBe('5');
    const res = await call(handler, '/', { 'x-forwarded-for': BLOCKED_IP, 'user-agent': BLOCKED_UA });
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-reason')).toBe('ip4');   // the block side, not a rule
    expect(res?.headers.get('x-block-rule')).toBeNull();
  });
});

import { afterEach, expect, it, vi } from 'vitest';
import { NextRequest, type NextFetchEvent } from 'next/server';
import { challengeGate } from '../src/challenge';
import { configure, getEngine, type ConfigureOptions } from '../src/engine';
import { camada } from '../src/middleware';
import { camadaRoute } from '../src/route';
import { withCamada } from '../src/with-camada';
import { BLOCKED_IP, CHALLENGED_IP, ENV, fakeAnalyst, fakeEvent } from './harness';

const AUTH = 'Bearer fake-token-0001-not-a-real-credential';
const TK = 'b3a18c6c56d5a2f7ad636bf950a919d7';
const API_TK = '94a6878c5d6bc3739f9a3d5644359a38';
const ON = { CAMADA_TOKEN_HASH: '1' };
const url = (path: string) => `https://app.example${path}`;

afterEach(() => {
  configure();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function setup(env: ConfigureOptions['env'] = {}, opts: Omit<ConfigureOptions, 'env' | 'fetchImpl'> = {}) {
  const a = fakeAnalyst();
  configure({
    ...opts,
    env: { ...ENV, CAMADA_KEY: 'ct_test_fixture_key.snap-test', CAMADA_TRUSTED_PROXY: 'hops:1', ...env },
    fetchImpl: a.fetchImpl,
  });
  return a;
}

async function prime() {
  const ev = fakeEvent();
  getEngine()!.snap.ensureFresh(ev.waitUntil.bind(ev));
  await ev.settled();
}

function middlewareRequest(path: string, headers: Record<string, string> = {}) {
  const ev = fakeEvent();
  const res = camada()(new NextRequest(url(path), { headers: { authorization: AUTH, ...headers } }), ev as unknown as NextFetchEvent);
  return { ev, res };
}

it.each([
  { label: 'off by default despite the snapshot', env: {}, opts: {}, tk: undefined },
  { label: 'on via env', env: ON, opts: {}, tk: TK },
  { label: 'off via an explicit override', env: ON, opts: { tokenHash: false }, tk: undefined },
])('ships middleware capture and synchronous block rows with hashing $label', async ({ env, opts, tk }) => {
  const a = setup(env, opts);
  a.config.tokenHash = true;
  await prime();
  const capture = middlewareRequest('/capture');
  expect((await capture.res)?.status).toBe(200);
  await capture.ev.settled();
  const block = middlewareRequest('/block', { 'x-forwarded-for': BLOCKED_IP });
  expect(block.res).toMatchObject({ status: 403 });
  await block.ev.settled();
  const rows = a.events.flat();
  expect(rows).toEqual([
    expect.objectContaining({ p: '/capture', st: null }),
    expect.objectContaining({ p: '/block', st: 403, blk: 'ip4' }),
  ]);
  for (const row of rows) {
    if (tk) expect(row).toHaveProperty('tk', tk);
    else expect(row).not.toHaveProperty('tk');
  }
});

it('ships tk when middleware serves a challenge', async () => {
  const a = setup(ON);
  a.v4 = true;
  await prime();
  const { ev, res } = middlewareRequest('/challenge', { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP });
  expect(await res).toMatchObject({ status: 403 });
  await ev.settled();
  expect(a.events.flat()).toEqual([expect.objectContaining({ st: 403, blk: 'challenge', tk: TK })]);
});

it('ships tk on a signalled challenge gate row', async () => {
  const a = setup(ON);
  const res = await challengeGate(new Request(url('/gate'), {
    headers: { authorization: AUTH, accept: 'application/json', 'x-forwarded-for': CHALLENGED_IP },
  }), () => new Response(null));
  expect(res.headers.get('x-camada-challenge')).toBe('1');
  await vi.waitFor(() => expect(a.events.flat()).toEqual([expect.objectContaining({ chs: 1, tk: TK })]));
});

it('ships tk when the beacon route blocks a request', async () => {
  const a = setup(ON);
  await prime();
  const res = await camadaRoute().GET(new Request(url('/api/camada/b.js'), {
    headers: { authorization: AUTH, 'x-forwarded-for': BLOCKED_IP },
  }));
  expect(res.status).toBe(403);
  await vi.waitFor(() => expect(a.events.flat()).toEqual([expect.objectContaining({ st: 403, blk: 'ip4', tk: TK })]));
});

it.each([
  { label: 'env enables hashing', env: ON, opts: {}, tk: TK },
  { label: 'the option disables hashing', env: ON, opts: { tokenHash: false }, tk: undefined },
  { label: 'the option selects the extra header', env: { ...ON, CAMADA_TOKEN_HEADER: 'x-other' }, opts: { tokenHeader: 'X-Api-Key' }, tk: API_TK },
])('passes resolved config to withCamada when $label', async ({ env, opts, tk }) => {
  const a = setup(env, opts);
  vi.stubGlobal('fetch', a.fetchImpl);
  const res = await withCamada(() => new Response('ok'))(new Request(url('/wrapped'), {
    headers: { authorization: AUTH, 'x-api-key': 'fake-api-key-0007' },
  }));
  expect(await res.text()).toBe('ok');
  await vi.waitFor(() => expect(a.events.flat()).toEqual([expect.objectContaining({ p: '/wrapped', st: 200 })]));
  const [row] = a.events.flat();
  if (tk) expect(row).toHaveProperty('tk', tk);
  else expect(row).not.toHaveProperty('tk');
});

it('strips tk, bf and upf from a beacon even with hashing enabled', async () => {
  const a = setup(ON);
  const res = await camadaRoute().POST(new Request(url('/api/camada/fp'), {
    method: 'POST', headers: { authorization: AUTH },
    body: JSON.stringify({ rid: 'beacon', tk: TK, bf: ['x'], upf: ['y'] }),
  }));
  expect(res.status).toBe(204);
  expect(a.events.flat()).toEqual([expect.objectContaining({ rid: 'beacon', sig: 1 })]);
  const [row] = a.events.flat();
  for (const key of ['tk', 'bf', 'upf']) expect(row).not.toHaveProperty(key);
});

it('warns once per engine for an ignored extra header and hashes Authorization', async () => {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const a = setup({ ...ON, CAMADA_TOKEN_HEADER: 'cookie' });
  await prime();
  for (const path of ['/first', '/second']) {
    const { ev, res } = middlewareRequest(path, { cookie: 'session=fake-cookie-value' });
    expect(await res).toMatchObject({ status: 200 });
    await ev.settled();
  }
  expect(warn).toHaveBeenCalledTimes(1);
  expect(a.events.flat()).toEqual([
    expect.objectContaining({ p: '/first', tk: TK }),
    expect.objectContaining({ p: '/second', tk: TK }),
  ]);
});

it('serves a scheme-only Authorization and ships without tk', async () => {
  const a = setup(ON);
  const { ev, res } = middlewareRequest('/scheme-only', { authorization: 'Bearer' });
  expect(await res).toMatchObject({ status: 200 });
  await ev.settled();
  expect(a.events.flat()).toEqual([expect.objectContaining({ p: '/scheme-only' })]);
  expect(a.events.flat()[0]).not.toHaveProperty('tk');
});

it('serves the request and ships without tk when signing the credential rejects', async () => {
  const a = setup(ON);
  const log = vi.spyOn(console, 'error').mockImplementation(() => {});
  const subtle = crypto.subtle;
  const sign = subtle.sign.bind(subtle);
  let hashAttempted = false;
  vi.spyOn(subtle, 'sign').mockImplementation((algorithm, key, data) => {
    if (new TextDecoder().decode(data).startsWith('tok:')) {
      hashAttempted = true;
      return Promise.reject(new Error('WebCrypto signing failed'));
    }
    return sign(algorithm, key, data);
  });
  const { ev, res } = middlewareRequest('/hash-failed');
  expect(await res).toMatchObject({ status: 200 });
  await ev.settled();
  expect(hashAttempted).toBe(true);
  expect(log).toHaveBeenCalledWith(expect.any(String), 'token hash failed; event ships without tk');
  expect(a.events.flat()).toEqual([expect.objectContaining({ p: '/hash-failed' })]);
  expect(a.events.flat()[0]).not.toHaveProperty('tk');
});

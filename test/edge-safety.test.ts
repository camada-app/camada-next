// The edge-safety PROOF for the middleware entry, in two halves:
//   1. Bundle src/middleware.ts (and its whole import graph) with esbuild platform
//      'neutral', where node: built-ins do not resolve — any `import 'node:*'` anywhere in
//      the graph fails the bundle step. A canary test pins that the mechanism really trips.
//   2. Execute the bundle inside a bare @edge-runtime/vm (no Node globals at all) and drive
//      a real cold -> blocked flow through it against the golden snapshot fixture.
// next/server is stubbed (it is Next's own edge-safe surface); everything camada ships —
// middleware + engine + @camada/core — is bundled and executed for real.
import { describe, it, expect } from 'vitest';
import { build } from 'esbuild';
import { EdgeVM } from '@edge-runtime/vm';
import { fileURLToPath } from 'node:url';
import { fakeAnalyst, ENV, BLOCKED_IP } from './harness';

const root = fileURLToPath(new URL('..', import.meta.url));

const STUB_NEXT_SERVER = `export class NextResponse extends Response {
  static next(init) {
    const headers = new Headers();
    if (init && init.request && init.request.headers) {
      for (const [k, v] of init.request.headers) headers.set('x-middleware-request-' + k, v);
    }
    return new NextResponse(null, { status: 200, headers });
  }
}`;

async function bundle(entry: string): Promise<string> {
  const result = await build({
    stdin: { contents: entry, resolveDir: root, loader: 'ts' },
    bundle: true,
    write: false,
    platform: 'neutral',   // node built-ins do NOT resolve: a node: import fails right here
    format: 'iife',
    globalName: '__camada_mw',
    logLevel: 'silent',
    plugins: [{
      name: 'stub-next-server',
      setup(b) {
        b.onResolve({ filter: /^next\/server$/ }, () => ({ path: 'next-server', namespace: 'stub' }));
        b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: STUB_NEXT_SERVER, loader: 'js' }));
      },
    }],
  });
  return result.outputFiles[0].text;
}

const ENTRY = `export { camada } from './src/middleware'; export { configure } from './src/engine';`;

describe('edge-safety proof', () => {
  it('canary: the mechanism fails the bundle when a node: import enters the graph', async () => {
    await expect(bundle(`import 'node:crypto';\n${ENTRY}`)).rejects.toThrow(/node:crypto/);
  });

  it('the middleware graph bundles for a bare edge runtime and runs inside @edge-runtime/vm', async () => {
    const code = await bundle(ENTRY);
    const vm = new EdgeVM();
    vm.evaluate(code);
    const api = vm.evaluate('__camada_mw') as {
      camada: () => (req: unknown, ev: unknown) => Response | undefined;
      configure: (o: unknown) => void;
    };
    // requests are created inside the VM realm, exactly as the edge runtime would
    const makeReq = vm.evaluate('(url, headers) => new Request(url, { headers })') as
      (url: string, headers: Record<string, string>) => unknown;

    const a = fakeAnalyst();
    api.configure({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' }, fetchImpl: a.fetchImpl });
    const handler = api.camada();

    const promises: Promise<unknown>[] = [];
    const ev = { waitUntil: (p: Promise<unknown>) => promises.push(p) };

    const cold = handler(makeReq('https://app.example/', { 'x-forwarded-for': BLOCKED_IP }), ev);
    expect(cold?.status).toBe(200);                    // cold start fails open
    expect(promises.length).toBeGreaterThan(0);        // snapshot load handed to waitUntil
    await Promise.all(promises.splice(0));

    const res = handler(makeReq('https://app.example/', { 'x-forwarded-for': BLOCKED_IP }), ev);
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-block-reason')).toBe('ip4');
    await Promise.all(promises.splice(0));
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs.some((e) => e.st === 403 && e.tap === 'sdk-next' && e.ip === BLOCKED_IP)).toBe(true);
  });
});

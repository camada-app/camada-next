// Local copy of camada-node's fakeAnalyst harness (copied, never imported across repos): an
// in-process fetch router standing in for the analyst Worker (GET /snapshot, POST /e,
// POST /fp), pinned to the same golden fixtures through the file: symlink
// node_modules/@camada/core/test/fixtures.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const FIX = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk3/', import.meta.url));
const FIX5 = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/blk5/', import.meta.url));
export const BIN = readFileSync(FIX + 'v3-basic.bin');
export const META = JSON.stringify(JSON.parse(readFileSync(FIX + 'v3-basic.meta.json', 'utf8')));
export const V4_BIN = readFileSync(FIX + 'v4-basic.bin');
export const V4_META = JSON.stringify(JSON.parse(readFileSync(FIX + 'v4-basic.meta.json', 'utf8')));
export const V5_BIN = readFileSync(FIX5 + 'v5-rules.bin');
export const V5_META = JSON.stringify(JSON.parse(readFileSync(FIX5 + 'v5-rules.meta.json', 'utf8')));
export const BLOCKED_IP = '203.0.113.66';      // an ip4 entry in v3-basic and v4-basic
export const CHALLENGED_IP = '192.0.2.20';     // a challenge-only ip4 entry in v4-basic
export const ALLOWED_IP = '10.0.0.7';          // allow-listed inside the blocked 10.0.0.0/8
// v5-rules only (§D3): the ordered custom rules the golden container carries.
export const RULE_BLOCKED_IP = '198.51.100.7';   // builtin:block, a manual-block entry
export const SKIP_PATH = '/healthz';             // cr_00000000000a, skip — beats every side
export const RULE_BLOCKED_PATH = '/api/v2/dump'; // cr_00000000000c, block by path regex
export const WARN_UA = 'Scrapy/2.11 (+https://scrapy.org)';   // cr_00000000000e, warn
export const BLOCKED_UA = 'curl/8.4.0';                       // cr_00000000000f, block
export const BLOCKED_HEADER = 'x-api-key';                    // cr_000000000019, `header is` → block
export const BLOCKED_HEADER_VALUE = 'leaked-key-1';

export interface FakeAnalyst {
  fetchImpl: typeof fetch;
  events: unknown[][];          // batches POSTed to /e
  beacons: Array<{ body: string; clientIp: string | null }>;
  sdkHeaders: string[];         // x-camada-sdk seen on /snapshot and /e
  config: Record<string, unknown>;
  snapshotDown: boolean;
  ingestDown: boolean;
  v4: boolean;                  // serve the v4 golden container instead of v3
  v5: boolean;                  // serve the v5 golden container (custom rules); wins over v4
  snapshotVersions: string[];   // x-camada-snapshot seen on /snapshot
}

export function fakeAnalyst(): FakeAnalyst {
  const a: FakeAnalyst = {
    events: [], beacons: [], sdkHeaders: [], snapshotVersions: [], snapshotDown: false, ingestDown: false, v4: false, v5: false,
    config: { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 },
    fetchImpl: (async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith('/snapshot') || u.endsWith('/e')) a.sdkHeaders.push(new Headers(init?.headers).get('x-camada-sdk') ?? '');
      if (u.endsWith('/snapshot')) {
        a.snapshotVersions.push(new Headers(init?.headers).get('x-camada-snapshot') ?? '');
        if (a.snapshotDown) throw new Error('ECONNREFUSED');
        // 200 body frame: [u32 LE meta-length][meta JSON][BLK bin]. Which container a tenant
        // has is the server's business: a v5 asker is answered with v4 or v3 when that is all
        // this tenant published, exactly as §D3 says.
        const meta = a.v5 ? V5_META : a.v4 ? V4_META : META;
        const body = a.v5 ? V5_BIN : a.v4 ? V4_BIN : BIN;
        const m = new TextEncoder().encode(meta);
        const f = new Uint8Array(4 + m.length + body.length);
        new DataView(f.buffer).setUint32(0, m.length, true);
        f.set(m, 4); f.set(new Uint8Array(body), 4 + m.length);
        return new Response(f, {
          status: 200,
          headers: { etag: `"${JSON.parse(meta).version}"`, 'x-camada-config': JSON.stringify(a.config) },
        });
      }
      if (a.ingestDown) throw new Error('ECONNREFUSED');
      if (u.endsWith('/e')) { a.events.push(JSON.parse(init!.body as string)); return new Response(null, { status: 202 }); }
      if (u.endsWith('/fp')) {
        a.beacons.push({ body: init!.body as string, clientIp: new Headers(init?.headers).get('x-client-ip') });
        return new Response(null, { status: 202 });
      }
      throw new Error('unmocked fetch: ' + u);
    }) as typeof fetch,
  };
  return a;
}

export const ENV = {
  CAMADA_KEY: 'tok-test.snap-test',
  CAMADA_INGEST_URL: 'https://analyst.test',
} as Record<string, string>;

/** A NextFetchEvent stand-in that collects waitUntil promises. */
export function fakeEvent() {
  const promises: Promise<unknown>[] = [];
  return {
    promises,
    waitUntil(p: Promise<unknown>) { promises.push(p); },
    async settled() { await Promise.all(this.promises.splice(0)); },
  };
}

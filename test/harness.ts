// Local copy of camada-node's fakeAnalyst harness (copied, never imported across repos): an
// in-process fetch router standing in for the analyst Worker (GET /snapshot, POST /e,
// POST /fp), pinned to the same golden fixtures through the file: symlink
// node_modules/@camada/core/test/fixtures.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const FIX = fileURLToPath(new URL('../node_modules/@camada/core/test/fixtures/', import.meta.url));
export const BIN = readFileSync(FIX + 'snap-basic.bin');
export const META = JSON.stringify(JSON.parse(readFileSync(FIX + 'snap-basic.meta.json', 'utf8')));
export const BLOCKED_IP = '203.0.113.66';   // an ip4 entry in snap-basic

export interface FakeAnalyst {
  fetchImpl: typeof fetch;
  events: unknown[][];          // batches POSTed to /e
  beacons: Array<{ body: string; clientIp: string | null }>;
  config: Record<string, unknown>;
  snapshotDown: boolean;
  ingestDown: boolean;
}

export function fakeAnalyst(): FakeAnalyst {
  const a: FakeAnalyst = {
    events: [], beacons: [], snapshotDown: false, ingestDown: false,
    config: { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 },
    fetchImpl: (async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith('/snapshot')) {
        if (a.snapshotDown) throw new Error('ECONNREFUSED');
        // 200 body frame: [u32 LE meta-length][meta JSON][BLK3 bin]
        const m = new TextEncoder().encode(META);
        const f = new Uint8Array(4 + m.length + BIN.length);
        new DataView(f.buffer).setUint32(0, m.length, true);
        f.set(m, 4); f.set(new Uint8Array(BIN), 4 + m.length);
        return new Response(f, {
          status: 200,
          headers: { etag: `"${JSON.parse(META).version}"`, 'x-camada-config': JSON.stringify(a.config) },
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

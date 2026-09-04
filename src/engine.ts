// The lazy singleton engine behind every @camada/next entry point: one SnapshotClient in
// 'lazy' mode (edge runtime — ensureFresh per request, no interval timers) plus one
// EventQueue, wired from the environment on first use. Unconfigured -> engine is null, every
// entry point stays inert, and one rate-limited console.error says why. CAMADA_DISABLED=1 is
// checked per request (isDisabled), never memoized here.
//
// This module is part of the middleware's import graph and therefore MUST stay
// edge-runtime-safe: Web APIs and process.env reads only, no node: imports.
import {
  SnapshotClient, EventQueue, parseKey, parseTrustedProxyEnv, logRateLimited,
  type TrustedProxyConfig,
} from '@camada/core';

import { SDK_ID } from './version';

export { parseTrustedProxyEnv };   // re-export for callers that had reached into this module

export interface ResolvedEnv {
  ingestToken: string;
  snapToken: string;
  secret: string;                            // HMAC key for the challenge nonce/cookie — never leaves the process
  ingestUrl: string;
  snapshotUrl: string;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
}

/** Returns null (SDK stays inert, one log line) rather than throwing on bad config. */
export function resolveEnv(env: Record<string, string | undefined>): ResolvedEnv | null {
  const key = parseKey(env.CAMADA_KEY);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (env.CAMADA_INGEST_URL || 'https://in.camada.dev').replace(/\/$/, '');   // PLACEHOLDER default — confirm the production ingest domain before any npm publish
  return {
    ingestToken, snapToken, ingestUrl,
    secret: env.CAMADA_KEY || `${ingestToken}.${snapToken}`,
    snapshotUrl: env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    // On Vercel the platform overwrites X-Forwarded-For, so its rightmost entry is
    // trustworthy: default to vercel mode there unless explicitly overridden.
    trustedProxy: parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY) ?? (env.VERCEL ? { mode: 'vercel' } : null),
  };
}

export interface Engine {
  env: ResolvedEnv;
  snap: SnapshotClient;
  queue: EventQueue;
  fetchImpl: typeof fetch;   // for the beacon relay; snapshot/queue carry their own copy
}

export interface ConfigureOptions {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  challenge?: boolean;        // enforce `challenge` verdicts with the first-party page (default true)
  snapshotVersion?: 3 | 4;    // 3 opts out of the v4 allow/challenge sections
}

let engine: Engine | null | undefined;   // undefined = not built yet; null = unconfigured
let overrides: ConfigureOptions = {};

/** Internal test/reset hook (mirrors @camada/node's configure): replaces the singleton. */
export function configure(opts: ConfigureOptions = {}): void {
  engine?.snap.stop();
  engine?.queue.stop();
  overrides = opts;
  engine = undefined;
}

function envSource(): Record<string, string | undefined> {
  return overrides.env ?? (typeof process !== 'undefined' && process.env ? process.env : {});
}

/** Kill switch, checked per request so an env flip disables camada without a code change. */
export function isDisabled(): boolean {
  return envSource().CAMADA_DISABLED === '1';
}

/** SDK-04 is on unless the app opts out in code or with CAMADA_CHALLENGE=0. */
export function challengeEnabled(): boolean {
  return overrides.challenge !== false && envSource().CAMADA_CHALLENGE !== '0';
}

export function getEngine(): Engine | null {
  if (engine !== undefined) return engine;
  const env = resolveEnv(envSource());
  if (!env) {
    logRateLimited(new Error('CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive'));
    return (engine = null);
  }
  const fetchImpl = overrides.fetchImpl;
  const injected = fetchImpl ? { fetchImpl } : {};   // never pass an explicit undefined key
  engine = {
    env,
    fetchImpl: fetchImpl ?? fetch,
    snap: new SnapshotClient({ url: env.snapshotUrl, token: env.snapToken, mode: 'lazy', sdk: SDK_ID, snapshotVersion: overrides.snapshotVersion ?? 4, ...injected }),
    queue: new EventQueue({ url: env.ingestUrl, token: env.ingestToken, sdk: SDK_ID, ...injected }),
  };
  return engine;
}

/** The trusted-proxy config in force: explicit local/env override wins, then the
 *  server-delivered tenant config, then none (socket-less edge -> ip stays null). */
export function trustedProxy(e: Engine): TrustedProxyConfig | null {
  return e.env.trustedProxy ?? e.snap.config?.trusted_proxy ?? null;
}

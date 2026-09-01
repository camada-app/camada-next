// <CamadaBeacon/> — an async React Server Component for the app-router layout <head>: reads
// the middleware-stamped x-camada-rid request header (so the beacon POST joins the server's
// wire event) and renders the @camada/react beacon tag pointing at the camada route.
// 'next/headers' is imported lazily inside the component so this module only touches it
// server-side, in a request scope.
import { CamadaBeacon as Beacon } from '@camada/react';

export interface CamadaBeaconProps {
  /** Where camadaRoute() serves the beacon script. Default: '/api/camada/b.js'. */
  src?: string;
}

export async function CamadaBeacon({ src = '/api/camada/b.js' }: CamadaBeaconProps = {}) {
  let rid: string | null = null;
  try {
    const { headers } = await import('next/headers');
    rid = (await headers()).get('x-camada-rid');
  } catch { /* outside a request scope (static render, tests): beacon ships without a rid */ }
  return <Beacon src={src} rid={rid} />;
}

// @camada/next — the three-line install:
//   middleware.ts / proxy.ts:                 export default camada();
//   app/api/camada/[...camada]/route.ts:      export const { GET, POST } = camadaRoute();
//   app/layout.tsx <head>:                    <CamadaBeacon/>
// Plus track() for app-context outcomes from server actions / route handlers.
export { camada, type CamadaMiddlewareOptions, type MiddlewareResult } from './middleware';
export { camadaRoute } from './route';
export { challengeGate } from './challenge';
export { CamadaBeacon, type CamadaBeaconProps } from './beacon';
export { track } from './track';

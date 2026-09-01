// @camada/next — the three-line install:
//   middleware.ts / proxy.ts:                 export default camada();
//   app/api/camada/[...camada]/route.ts:      export const { GET, POST } = camadaRoute();
//   app/layout.tsx <head>:                    <CamadaBeacon/>
export { camada, type CamadaMiddlewareOptions } from './middleware';
export { camadaRoute } from './route';
export { CamadaBeacon, type CamadaBeaconProps } from './beacon';

import { defineConfig } from 'tsup';
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  external: [
    '@camada/core',
    '@camada/browser',
    '@camada/browser/iife-string',
    '@camada/react',
    'next',
    'next/server',
    'next/headers',
    'react',
    'react/jsx-runtime',
  ],
});

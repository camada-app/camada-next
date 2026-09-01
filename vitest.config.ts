import { defineConfig } from 'vitest/config';

// Default environment is node (route handlers run on either runtime). The middleware suite
// opts into the edge runtime per file via `// @vitest-environment edge-runtime`
// (@edge-runtime/vm), and test/edge-safety.test.ts additionally bundles the middleware
// entry for a bare edge runtime and executes it inside an EdgeVM with no Node globals.
export default defineConfig({
  test: {
    environment: 'node',
  },
});

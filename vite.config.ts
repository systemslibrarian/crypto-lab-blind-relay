import { defineConfig } from 'vitest/config';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));

// The hub's HPKE module (crypto-lab-hpke-envelope) is CONSUMED, never forked.
// Locally the hub is a sibling checkout; in CI the deploy workflow checks it
// out into ./hub/ because actions/checkout can only write inside the workspace.
const HUB_CANDIDATES = [
  path.resolve(here, '../crypto-lab-hpke-envelope/src/hpke'),
  path.resolve(here, 'hub/crypto-lab-hpke-envelope/src/hpke'),
];
const hubHpke = HUB_CANDIDATES.find((p) => existsSync(p));
if (!hubHpke) {
  throw new Error(
    'crypto-lab-hpke-envelope not found — clone it as a sibling of this repo ' +
      '(or into ./hub/). This lab consumes the hub HPKE module rather than rebuilding it.',
  );
}

export default defineConfig({
  base: '/crypto-lab-blind-relay/',
  resolve: {
    alias: { '@hub/hpke': hubHpke },
  },
  build: {
    target: 'es2022',
  },
  server: {
    fs: { allow: [here, path.resolve(here, '..')] },
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});

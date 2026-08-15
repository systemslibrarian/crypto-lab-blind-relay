import { defineConfig, devices } from '@playwright/test';

// Must be unique across the crypto-lab fleet. `reuseExistingServer` adopts
// whatever already listens here, so a shared port means this suite can scan a
// sibling lab's page and report its findings as ours. The old default was
// 4173 — vite preview's own default, so it collided not with one named lab
// but with any of the 170+ that had not been assigned a port, and with any
// stray `vite preview` on this machine. PW_PORT stays as a local escape
// hatch; it was never the fix, because what has to be unique is the
// committed default.
const PORT = Number(process.env.PW_PORT ?? 4678);
const BASE = '/crypto-lab-blind-relay/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});

import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: an exchange sealed and walked
 * through all nine pipeline steps, stepped back, auto-played and paused, the
 * collusion switch flipped on and off again, four clients simulated and joined
 * on size and on timing with padding off and then on, all three attacks fired
 * against the real decapsulation, the request re-run as a POST under
 * ChaCha20-Poly1305, the empty-query fallback taken, and every disclosure opened
 * by its own summary. Every resulting state is scanned in both themes at desktop
 * and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why reduced motion is
 * asked for rather than forced, why the lab's defaults are asserted rather than
 * assumed, why every step is scanned rather than only the last, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
    expectBaselineNotStale();
  });
}

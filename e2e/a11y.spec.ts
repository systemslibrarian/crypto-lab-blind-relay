import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal everything: run a real exchange, jump to the final step, flip the
 * collusion switch, fire all three attacks, and open every <details> — so the
 * axe scan covers the dynamic result regions, not just the initial page.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.locator('#run-btn').click();
  await expect(page.locator('#next-btn')).toBeEnabled();
  await page.locator('#all-btn').click();
  await page.locator('#collude-switch').click();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'true');
  for (const id of ['#attack-wrongkey', '#attack-tamper', '#attack-leak']) {
    await page.locator(id).click();
    await expect(page.locator('#attack-out .attack-out')).toBeVisible();
  }
  await page.locator('#crowd-btn').click();
  await expect(page.locator('#crowd-join')).toBeEnabled();
  await page.locator('#crowd-join').click();
  await expect(page.locator('#crowd-out .verdicts')).toBeVisible();
  await page.locator('#crowd-join-time').click();
  await expect(page.locator('#crowd-out .verdicts')).toBeVisible();
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => (d.open = true));
  });
  await page.waitForTimeout(300);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});

test('the demo teaches: size correlates without collusion, padding restores the anonymity set', async ({ page }) => {
  await page.goto('.');
  await page.locator('#crowd-btn').click();
  await page.locator('#crowd-join').click();
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('size alone');
  await expect(page.locator('#crowd-out .verdict-neutral')).toContainText('nothing was decrypted');
  await page.locator('#crowd-pad').check();
  await page.locator('#crowd-btn').click();
  await page.locator('#crowd-join').click();
  await expect(page.locator('#crowd-out .verdict-ok')).toContainText('anonymity set');
  // Padding beat the size join — the timing join must still identify everyone.
  await page.locator('#crowd-join-time').click();
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('arrival time alone');
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('padding fixed the sizes');
});

test('the demo teaches: collusion breaks privacy while crypto stays valid', async ({ page }) => {
  await page.goto('.');
  await page.locator('#run-btn').click();
  await page.locator('#all-btn').click();
  // Verdict separation before collusion: privacy holds.
  await expect(page.locator('#collude-out .verdict-ok')).toContainText('HOLDS');
  await page.locator('#collude-switch').click();
  // After collusion: crypto verdict unchanged-and-valid, privacy verdict alarm.
  await expect(page.locator('#collude-out .verdict-alarm')).toContainText('BROKEN');
  await expect(page.locator('#collude-out .verdict-neutral')).toContainText('verified');
  // The joined record names both halves of the split.
  await expect(page.locator('#collude-out .join-record')).toContainText('203.0.113.7');
  await expect(page.locator('#collude-out .join-record')).toContainText('WHAT:');
});

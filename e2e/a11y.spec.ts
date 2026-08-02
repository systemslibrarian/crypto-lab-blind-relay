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

/**
 * WCAG 1.4.11 regression: text-entry control boundaries (input/textarea/select
 * borders) must hit >= 3:1 against at least one adjacent surface, after
 * compositing translucent colors over the real ancestor backgrounds.
 */
async function measureControlBorders(
  page: Page,
): Promise<Array<{ sel: string; best: number }>> {
  return page.evaluate(() => {
    const parse = (c: string): number[] => {
      const m = c.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/);
      return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : [0, 0, 0, 0];
    };
    const comp = (fg: number[], bg: number[]): number[] =>
      [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat([1]);
    const lum = ([r, g, b]: number[]): number => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const ratio = (a: number[], b: number[]): number => {
      const l1 = lum(a);
      const l2 = lum(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };
    const effBg = (start: Element | null): number[] => {
      const stack: number[][] = [];
      let node: Element | null = start;
      while (node) {
        const c = parse(getComputedStyle(node).backgroundColor);
        if (c[3] > 0) stack.push(c);
        if (c[3] >= 1) break;
        node = node.parentElement;
      }
      let bg = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) bg = comp(stack[i], bg);
      return bg;
    };
    const TEXTY = ['', 'text', 'number', 'password', 'email', 'search', 'url', 'tel'];
    const out: Array<{ sel: string; best: number }> = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      if (el.tagName === 'INPUT' && !TEXTY.includes((el.getAttribute('type') || '').toLowerCase())) return;
      const cs = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if (cs.display === 'none' || cs.visibility === 'hidden' || rect.width === 0 || rect.height === 0) return;
      if ((parseFloat(cs.borderTopWidth) || 0) === 0) return;
      const outer = effBg(el.parentElement);
      const ownBg = parse(cs.backgroundColor);
      const inner = ownBg[3] >= 1 ? ownBg : comp(ownBg, outer);
      const borderRaw = parse(cs.borderTopColor);
      const best = Math.max(ratio(comp(borderRaw, outer), outer), ratio(comp(borderRaw, inner), inner));
      out.push({
        sel: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''),
        best: Math.round(best * 100) / 100,
      });
    });
    return out;
  });
}

for (const theme of ['dark', 'light'] as const) {
  test(`text control borders >= 3:1 — ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    }
    const rows = await measureControlBorders(page);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.filter((r) => r.best < 3)).toEqual([]);
  });
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

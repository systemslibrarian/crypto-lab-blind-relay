import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     opened with `addStyleTag({ content: '*{animation:none!important;
 *     transition:none!important}' })` and never asked for the preference at
 *     all. Overriding from the test bypasses this lab's own
 *     `@media (prefers-reduced-motion: ...)` handling instead of exercising it —
 *     and this lab's handling is the inverted form, `@media (prefers-reduced-
 *     motion: no-preference) { .wire-chip { transition: left .4s } }`, which a
 *     blanket override makes indistinguishable from a lab that never gated its
 *     motion at all. `boot` asks for the preference and asserts it took effect.
 *
 *  2. EVERY STATE IS SCANNED, NOT ONLY THE LAST ONE. The gate this replaces ran
 *     the exchange, jumped straight to the last step, flipped collusion on,
 *     fired all three attacks, ran the crowd and both joins — and then scanned
 *     ONCE. Each of those overwrites the previous one's output in the same
 *     container, so the alarm verdicts, the failure-path error strings and the
 *     un-colluded `HOLDS` tone were all built and thrown away unmeasured. It
 *     also jumped past seven of the nine pipeline steps, and the party cards it
 *     never rendered are most of the lab's content.
 *
 *  3. `<details>` ARE OPENED BY THEIR SUMMARIES. The old gate set `.open = true`
 *     on all four from script, so the shut state was never scanned and the open
 *     one was never reached the way a reader reaches it.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This
 * stylesheet is currently immune by construction: it declares no `@keyframes`
 * at all and gates its single transition the safe way round, by ADDING
 * `transition: left .4s` under `prefers-reduced-motion: no-preference` rather
 * than cancelling one under `reduce`. That immunity is a property of the CSS as
 * it stands today, not of the gate, which is exactly why the assertion is here:
 * the first `@keyframes` anyone adds is the one that can regress it.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * WCAG 1.4.11: a text-entry control whose only boundary is its border needs
 * that border at >= 3:1 against an adjacent surface.
 *
 * Carried over from the gate this replaces, which measured it once per theme on
 * the untouched page. It is folded into `scan` here instead, so it is measured
 * in every driven state and both viewports — the fields are the same three
 * throughout, but a state that restyles or re-enables one would otherwise go
 * unmeasured.
 *
 * The backdrop walk composites plain `rgba()`/`rgb()` only; an unparseable
 * value (a `color-mix()`) is treated as transparent and the walk continues
 * outward. That is sound here because every surface a control sits on —
 * `--surface`, `--surface-2`, `--bg` — is a flat hex, and the page's only
 * `color-mix()` surface is the hero aside, which contains no controls.
 */
export async function expectControlBordersContrast(page: Page, label: string): Promise<void> {
  const rows = await page.evaluate(() => {
    const parse = (c: string): number[] => {
      const m = c.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/);
      return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : [0, 0, 0, 0];
    };
    const comp = (fg: number[], bg: number[]): number[] =>
      [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat([1]);
    const lum = ([r, g, b]: number[]): number => {
      const f = (v: number): number => {
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
    const out: string[] = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      if (el.tagName === 'INPUT' && !TEXTY.includes((el.getAttribute('type') || '').toLowerCase()))
        return;
      const cs = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if (cs.display === 'none' || cs.visibility === 'hidden' || rect.width === 0 || rect.height === 0)
        return;
      if ((parseFloat(cs.borderTopWidth) || 0) === 0) return;
      const outer = effBg(el.parentElement);
      const ownBg = parse(cs.backgroundColor);
      const inner = ownBg[3] >= 1 ? ownBg : comp(ownBg, outer);
      const borderRaw = parse(cs.borderTopColor);
      const best = Math.max(ratio(comp(borderRaw, outer), outer), ratio(comp(borderRaw, inner), inner));
      if (best < 3) {
        out.push(
          `${Math.round(best * 100) / 100}:1 (needs 3:1) ` +
            `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''} border ${cs.borderTopColor}`
        );
      }
    });
    return out;
  });
  expect(rows, `text-control border contrast (WCAG 1.4.11) in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert THE LAB'S DEFAULTS rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: a silent no-op there would leave the gate
 * certifying a different rendering than the one it claims to.
 *
 * The default assertions matter for the same reason. Which half of this lab a
 * scan measures is decided by controls that ship in a particular position, and
 * one of them is a trap: `#crowd-pad` turns RFC 9292 padding on, and with it on
 * the size join returns an anonymity set (`verdict-ok`) instead of identifying
 * every client (`verdict-alarm`). Had it shipped checked, a gate that pressed
 * the join button would have scanned the passing tone forever. It ships
 * unchecked, and the drive runs both settings.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // `index.html` ships only the hero and an empty `<main id="lab-main">`; every
  // panel is written into it by `src/main.ts`, so a navigation that resolves
  // proves nothing.
  await expect(page.locator('#lab-main section.panel')).toHaveCount(9);
  await expect(page.locator('.party')).toHaveCount(4);

  // Defaults, asserted:
  //  - the three request controls sit where the lab shipped them, so the first
  //    exchange the drive runs is a GET sealed under AES-128-GCM;
  await expect(page.locator('#query-input')).toHaveValue('chest pain symptoms');
  await expect(page.locator('#method-select')).toHaveValue('GET');
  await expect(page.locator('#aead-select')).toHaveValue('1');
  //  - padding is OFF, so the size join identifies people rather than returning
  //    an anonymity set (see the note above);
  await expect(page.locator('#crowd-pad')).not.toBeChecked();
  //  - every control that needs an exchange first is locked, and that locked
  //    page is a real state a visitor lands in, scanned before any unlock;
  for (const id of ['#play-btn', '#back-btn', '#next-btn', '#all-btn']) {
    await expect(page.locator(id)).toBeDisabled();
  }
  await expect(page.locator('#collude-switch')).toBeDisabled();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'false');
  for (const id of ['#attack-wrongkey', '#attack-tamper', '#attack-leak']) {
    await expect(page.locator(id)).toBeDisabled();
  }
  for (const id of ['#crowd-join', '#crowd-join-time']) {
    await expect(page.locator(id)).toBeDisabled();
  }
  //  - and nothing has been computed: no message on the wire, no facts in the
  //    party cards, no disclosure open.
  await expect(page.locator('#wire-chip')).toBeHidden();
  await expect(page.locator('.party .fact')).toHaveCount(4);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex key material and full request
 * lines into narrow grid cells, lays the knowledge split out as a four-column
 * grid, and carries a five-column architecture comparison whose table declares
 * `min-width: 720px`.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has exactly that decoy:
    // `table.cmp` is `min-width: 720px` inside `.cmp-wrap`, which scrolls.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * `.cmp-wrap` is this lab's case and already carries the tabindex; the
 * assertion is what keeps it there, and what catches the next scroller — the
 * correlation logs and the key-schedule columns are all one long value away
 * from becoming one.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints a banner and fails at the
 * end, so a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `expectNotBlank` — the reduced-motion end-state check above.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less element hides, and `aria-required-children`,
 *    which is where an empty `role="list"` hides. Both are defects that never
 *    reach the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - control-border contrast — WCAG 1.4.11, which axe does not check.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softAsync(() => expectControlBordersContrast(page, label));
  await softAsync(() => expectScrollersReachable(page, label));
  await softAsync(() => expectNoHorizontalOverflow(page, label));
  await expectNoNewNonTextFailures(page, label);
}

async function softAsync(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ALARM STATES ARE THE LESSON, and this lab renders them as PAIRS: every
 *    outcome prints a neutral "Cryptographic result" beside an ok-or-alarm
 *    "Privacy verdict", because its whole thesis is that the two can disagree.
 *    `.verdict-ok`, `.verdict-alarm` and `.verdict-neutral` are three distinct
 *    ink/border pairs and each only exists in some states, so every one of them
 *    is driven and scanned where it appears.
 *
 *  - EVERY STEP OF THE PIPELINE IS SCANNED. The party cards are the lab's main
 *    content and they are rebuilt from `computeViews` at each of the nine steps,
 *    growing fact rows and `fact-cannot` rows as the message moves. The gate
 *    this replaces jumped straight to step 9 and scanned that alone.
 *
 *  - BOTH SETTINGS OF THE PADDING FORK ARE DRIVEN, and both joins are run under
 *    each, because that is what turns `verdict-alarm` into `verdict-ok` and
 *    back.
 *
 *  - COMPLETION IS WAITED ON, NEVER TIMED. Every button here does real HPKE
 *    work, so each step waits on output the lab itself produces — a verdict
 *    class, a button re-enabling, a step counter — not on a fixed delay. The one
 *    exception is auto-play, which is a 1600ms interval by design; the drive
 *    stops it and scans the settled page rather than racing it.
 *
 *  - `<details>` ARE OPENED BY THEIR OWN SUMMARIES, one at a time, so the shut
 *    state is scanned too and a failure names the panel it belongs to.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  const status = page.locator('#step-status');

  await scanAt('first paint, nothing run, every dependent control locked');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── The exchange, then every one of its nine steps ───────────────────────
  await page.locator('#run-btn').click();
  await expect(status).toContainText('Step 1 of 9');
  await expect(page.locator('#next-btn')).toBeEnabled();
  await expect(page.locator('#back-btn')).toBeDisabled();
  await scanAt('exchange sealed, step 1 of 9 — Back still locked at the first step');

  for (let step = 2; step <= 9; step++) {
    await page.locator('#next-btn').click();
    await expect(status).toContainText(`Step ${step} of 9`);
    await scanAt(`pipeline step ${step} of 9`);
  }
  await expect(page.locator('#next-btn')).toBeDisabled();
  await expect(page.locator('#all-btn')).toBeDisabled();

  await page.locator('#back-btn').click();
  await expect(status).toContainText('Step 8 of 9');
  await scanAt('stepped back to 8 of 9, Next unlocked again');

  // Auto-play is the one timed thing on the page. Start it, confirm the button
  // took its running label, stop it, and scan the page it settled on — racing a
  // 1600ms repaint with an axe pass would measure a state that no longer exists
  // by the time the assertion names it.
  await page.locator('#play-btn').click();
  await expect(page.locator('#play-btn')).toContainText('Pause');
  await page.locator('#play-btn').click();
  await expect(page.locator('#play-btn')).toContainText('Play all steps');
  await scanAt('auto-play started and paused');

  await page.locator('#all-btn').click();
  await expect(status).toContainText('Step 9 of 9');
  await scanAt('jumped to the end of the pipeline');

  // ── Collusion: the same crypto, two opposite privacy verdicts ────────────
  await expect(page.locator('#collude-out .verdict-ok')).toContainText('HOLDS');
  await scanAt('collusion off — crypto neutral, privacy HOLDS');

  await page.locator('#collude-switch').click();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#collude-out .verdict-alarm')).toContainText('BROKEN');
  await expect(page.locator('#collude-out .join-record')).toBeVisible();
  await scanAt('collusion on — joined log, privacy BROKEN, crypto still verified');

  await page.locator('#collude-switch').click();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#collude-out .verdict-ok')).toContainText('HOLDS');
  await scanAt('collusion switched back off');

  // ── Correlation without collusion: both joins, both padding settings ─────
  await page.locator('#crowd-btn').click();
  await expect(page.locator('#crowd-join')).toBeEnabled();
  await expect(page.locator('#crowd-out .sched-grid')).toBeVisible();
  await scanAt('four clients simulated, unpadded — both logs printed');

  await page.locator('#crowd-join').click();
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('size alone');
  await scanAt('size join, unpadded — identified by ciphertext length alone');

  await page.locator('#crowd-join-time').click();
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('arrival time alone');
  await scanAt('timing join, unpadded');

  await page.locator('#crowd-pad').check();
  await expect(page.locator('#crowd-join')).toBeDisabled();
  await expect(page.locator('#crowd-out')).toContainText('Padding ON');
  await scanAt('padding toggled on — the crowd invalidated, joins locked again');

  await page.locator('#crowd-btn').click();
  await expect(page.locator('#crowd-join')).toBeEnabled();
  await scanAt('four clients simulated, padded to a uniform length');

  await page.locator('#crowd-join').click();
  await expect(page.locator('#crowd-out .verdict-ok')).toContainText('anonymity set');
  await scanAt('size join, padded — the ok tone the unpadded run never shows');

  await page.locator('#crowd-join-time').click();
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText('padding fixed the sizes');
  await scanAt('timing join, padded — padding changed nothing here');

  // ── Break it: three attacks against the real decapsulation ───────────────
  await page.locator('#attack-wrongkey').click();
  await expect(page.locator('#attack-out .err')).toBeVisible();
  await expect(page.locator('#attack-out .verdict-ok')).toContainText('HOLDS');
  await scanAt('wrong-key attack — AEAD failed closed, error string rendered');

  await page.locator('#attack-tamper').click();
  await expect(page.locator('#attack-out .verdict-ok')).toContainText('HOLDS');
  await scanAt('tamper attack — one flipped byte rejected');

  await page.locator('#attack-leak').click();
  await expect(page.locator('#attack-out .verdict-alarm')).toContainText('BROKEN');
  await scanAt('leaked-key attack — a valid decryption IS the alarm');

  // ── The other branch of the request fork: POST under ChaCha20-Poly1305 ───
  await page.locator('#query-input').fill('a note I would rather not have attributed to me');
  await page.locator('#method-select').selectOption('POST');
  await page.locator('#aead-select').selectOption('3');
  await page.locator('#run-btn').click();
  await expect(status).toContainText('Step 1 of 9');
  // Running again resets collusion and clears the attack output — an empty
  // result region under buttons that are enabled again is its own state.
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#attack-out')).toBeEmpty();
  await scanAt('re-run as a POST under ChaCha20-Poly1305, previous results cleared');

  await page.locator('#all-btn').click();
  await expect(status).toContainText('Step 9 of 9');
  await scanAt('POST exchange stepped to the end');

  // The empty-input branch: the field falls back to its default query rather
  // than sealing an empty request.
  await page.locator('#query-input').fill('');
  await page.locator('#run-btn').click();
  await expect(status).toContainText('Step 1 of 9');
  await scanAt('empty query field — the lab falls back to its default request');

  // ── Every disclosure, opened the way a reader opens it ───────────────────
  const count = await page.locator('details').count();
  expect(count, 'the four expert disclosures').toBe(4);
  for (let i = 0; i < count; i++) {
    const d = page.locator('details').nth(i);
    await d.locator('> summary').click();
    await expect(d).toHaveAttribute('open', '');
    await scanAt(`disclosure ${i + 1} of ${count} open`);
  }
}

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on functional correctness;
 * this gates them on accessibility the same way. Scans the full page — with
 * every collapsible expanded and the live proof/tamper output rendered — in
 * both the dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Settle motion through the real media query the stylesheet already honours
 * rather than by injecting test-only CSS, so what axe measures is a state the
 * page can genuinely be in. Applied per test because on this Playwright
 * version `test.use({ reducedMotion })` did not reliably reach the context;
 * the assertion makes a silent no-op impossible.
 */
async function reduceMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
}

/**
 * Wait until nothing is animating before axe reads colours. A theme swap plus a
 * freshly revealed panel leave transitions in flight for several frames, and a
 * scan that samples inside that window reads half-swapped colour pairs the page
 * never actually renders. The old spec hid this by injecting
 * `transition-duration: 0s !important`, which also meant the suite could never
 * observe a transition-related defect.
 */
async function settle(page: Page): Promise<void> {
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  await expect
    .poll(() => page.evaluate(() => document.getAnimations().length), { timeout: 10_000 })
    .toBe(0);
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(resolve)));
}

async function revealEverything(page: Page): Promise<void> {
  // Expand any native disclosure widgets (none today, but future-proof).
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled / hidden panels.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/**
 * Drive the interactive builder so the proof/tamper output regions (which only
 * render after user actions) are present in the DOM when axe scans.
 */
async function exerciseApp(page: Page): Promise<void> {
  await page.locator('#build-tree').click();
  // Select a leaf, then generate the inclusion proof.
  await page.locator('[data-leaf-index="1"]').first().click();
  await page.locator('#generate-proof').click();
  await expect(page.locator('.proof-status')).toBeVisible();
  // Enter "walk the proof" mode and advance one level so the walk readout,
  // running-hash / active-sibling node highlights, and step-mode UI are scanned.
  await page.locator('#walk-start').click();
  await expect(page.locator('.walk-readout')).toBeVisible();
  await page.locator('#walk-next').click();
  // Reveal all levels again so the completed equality panel is present too.
  await page.locator('#walk-all').click();
  await expect(page.locator('.equality')).toBeVisible();
  // Open the gated Advanced subsection (odd-node selector + malleability panel).
  await page.locator('#advanced-odd > summary').click();
  await expect(page.locator('.mall-panel')).toBeVisible();
  // Tamper to render the tampered-node / invalid-proof output.
  await page.locator('#tamper-leaf').click();
  await expect(page.locator('.proof-panel')).toContainText('PROOF INVALID');

  // Both exhibits below were added after this scan was written and had never
  // been looked at in either theme. Drive each to both of its verdict colours
  // — a forgery accepted and rejected, an audit that passes and one that
  // fails — since a red verdict and a green one are different colour pairs.
  await page.locator('[data-ds-mode="rfc6962"]').click();
  await expect(page.locator('#sp-verdict')).toContainText('FORGERY REJECTED');
  await page.locator('[data-ds-mode="naive"]').click();
  await expect(page.locator('#sp-verdict')).toContainText('FORGERY ACCEPTED');
  await page.locator('[data-history="rewrite"]').click();
  await expect(page.locator('#cons-verdict')).toContainText('HISTORY TAMPERING DETECTED');
  await page.locator('[data-history="append"]').click();
  await expect(page.locator('#cons-verdict')).toContainText('APPEND-ONLY CONFIRMED');

  await revealEverything(page);
}

/** The stale-list banners are their own colour pair and their own scan. */
async function exerciseStaleState(page: Page): Promise<void> {
  await page.locator('#build-tree').click();
  await page.locator('#generate-proof').click();
  await expect(page.locator('.proof-status')).toBeVisible();
  await page.locator('#leaf-input').fill(['alpha', 'bravo', 'charlie', 'delta'].join('\n'));
  await expect(page.locator('.stale-notice')).toHaveCount(3);
  await revealEverything(page);
}

test.beforeEach(async ({ page }) => {
  await reduceMotion(page);
  await page.goto('.');
  await expect(page.locator('#app')).toBeVisible();
  const reduced = await page.evaluate(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  expect(reduced, 'reduced-motion emulation did not take effect').toBe(true);
});

async function useLightTheme(page: Page): Promise<void> {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await exerciseApp(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await useLightTheme(page);
  await exerciseApp(page);
  await scan(page);
});

test('no WCAG A/AA violations with the stale-list banners up (dark)', async ({ page }) => {
  await exerciseStaleState(page);
  await scan(page);
});

test('no WCAG A/AA violations with the stale-list banners up (light)', async ({ page }) => {
  await useLightTheme(page);
  await exerciseStaleState(page);
  await scan(page);
});

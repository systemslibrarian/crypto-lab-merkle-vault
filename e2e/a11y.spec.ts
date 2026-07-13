import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on functional correctness;
 * this gates them on accessibility the same way. Scans the full page — with
 * every collapsible expanded and the live proof/tamper output rendered — in
 * both the dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animations/transitions/opacity so axe samples settled colors.
const FREEZE_CSS = `
  *, *::before, *::after {
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    transition-duration: 0s !important;
    transition-delay: 0s !important;
    caret-color: transparent !important;
  }
`;

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
  await page.addStyleTag({ content: FREEZE_CSS });
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
  await revealEverything(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app')).toBeVisible();
  await exerciseApp(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await exerciseApp(page);
  await scan(page);
});

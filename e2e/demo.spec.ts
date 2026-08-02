import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the two exhibits this demo used to only describe: the
 * second-preimage forgery and the append-only consistency proof.
 *
 * Every assertion reads a value the browser computed during the run. The
 * verdicts come from verifyProof() and verifyConsistencyProof(); the hashes are
 * compared against each other rather than against pinned constants, so the test
 * fails if the page ever prints a conclusion its own arithmetic does not
 * support. Failure paths are asserted next to success paths throughout.
 */

const HEX64 = /^[0-9a-f]{64}$/;

async function gotoLab(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#section-preimage')).toBeVisible();
}

test.describe('second-preimage attack', () => {
  test('forges an accepted proof without domain separation', async ({ page }) => {
    await gotoLab(page);

    // Default view is the vulnerable convention, where the attack lands.
    await expect(page.locator('[data-ds-mode="naive"]')).toHaveAttribute('aria-checked', 'true');

    const node = (await page.locator('#sp-node').textContent())!.trim();
    const payload = (await page.locator('#sp-payload').textContent())!.trim();
    const leafHash = (await page.locator('#sp-leafhash').textContent())!.trim();
    const recomputed = (await page.locator('#sp-recomputed').textContent())!.trim();
    const committed = (await page.locator('#sp-committed').textContent())!.trim();

    expect(node).toMatch(HEX64);
    // The forged payload is exactly the two children concatenated: 64 bytes.
    expect(payload).toHaveLength(128);
    // Hashed as a leaf it IS the internal node — that is the whole attack.
    expect(leafHash).toBe(node);
    await expect(page.locator('#sp-collides')).toContainText('YES');
    // And the climb reaches the genuine committed root.
    expect(recomputed).toBe(committed);
    await expect(page.locator('#sp-verdict')).toContainText('FORGERY ACCEPTED');
    await expect(page.locator('#sp-verdict')).toHaveClass(/proof-invalid/);
    await expect(page.locator('#sp-cross')).toContainText('rejected');
  });

  test('the same forgery fails once RFC 6962 prefixes are restored', async ({ page }) => {
    await gotoLab(page);
    await page.locator('[data-ds-mode="rfc6962"]').click();
    await expect(page.locator('[data-ds-mode="rfc6962"]')).toHaveAttribute(
      'aria-checked',
      'true',
    );

    const node = (await page.locator('#sp-node').textContent())!.trim();
    const leafHash = (await page.locator('#sp-leafhash').textContent())!.trim();
    const recomputed = (await page.locator('#sp-recomputed').textContent())!.trim();
    const committed = (await page.locator('#sp-committed').textContent())!.trim();

    expect(leafHash).not.toBe(node);
    expect(recomputed).not.toBe(committed);
    await expect(page.locator('#sp-collides')).toContainText('NO');
    await expect(page.locator('#sp-verdict')).toContainText('FORGERY REJECTED');
    await expect(page.locator('#sp-verdict')).toHaveClass(/proof-valid/);
    await expect(page.locator('#sp-cross')).toContainText('accepted');
  });

  test('the attack tracks the tree the learner actually built', async ({ page }) => {
    await gotoLab(page);
    const before = (await page.locator('#sp-committed').textContent())!.trim();

    await page.locator('#leaf-input').fill(['one', 'two', 'three', 'four', 'five'].join('\n'));
    await page.locator('#build-tree').click();

    const after = (await page.locator('#sp-committed').textContent())!.trim();
    expect(after).not.toBe(before);
    // Still a live attack against the new tree, not a stale render.
    expect((await page.locator('#sp-leafhash').textContent())!.trim()).toBe(
      (await page.locator('#sp-node').textContent())!.trim(),
    );
    await expect(page.locator('#sp-verdict')).toContainText('FORGERY ACCEPTED');
  });
});

test.describe('consistency (append-only) proof', () => {
  test('an honest append verifies against the old root', async ({ page }) => {
    await gotoLab(page);

    await expect(page.locator('[data-history="append"]')).toHaveAttribute(
      'aria-checked',
      'true',
    );
    await expect(page.locator('#cons-verdict')).toContainText('APPEND-ONLY CONFIRMED');
    await expect(page.locator('#cons-verdict')).toHaveClass(/proof-valid/);

    const oldRoot = (await page.locator('#cons-oldroot').textContent())!.trim();
    const newRoot = (await page.locator('#cons-newroot').textContent())!.trim();
    expect(oldRoot).toMatch(HEX64);
    expect(newRoot).toMatch(HEX64);
    expect(oldRoot).not.toBe(newRoot);

    // The proof it verified from is the proof it printed, and it is short.
    const listed = await page.locator('.cons-proof li').count();
    const claimed = Number(
      ((await page.locator('#cons-size').textContent()) ?? '').replace(/\D/g, ''),
    );
    expect(listed).toBe(claimed);
    expect(listed).toBeGreaterThan(0);
    const n = Number(((await page.locator('#cons-n').textContent()) ?? '').replace(/\D/g, ''));
    expect(listed).toBeLessThanOrEqual(Math.ceil(Math.log2(n)) + 1);

    // Both halves of the replay land on the roots they are supposed to.
    expect((await page.locator('#cons-rebuilt-old').textContent())!.trim()).toBe(oldRoot);
    expect((await page.locator('#cons-rebuilt-new').textContent())!.trim()).toBe(newRoot);
    await expect(page.locator('[data-rebuilt-match="no"]')).toHaveCount(0);
  });

  test('a rewritten historical entry is caught', async ({ page }) => {
    await gotoLab(page);
    const honestOldRoot = (await page.locator('#cons-oldroot').textContent())!.trim();

    await page.locator('[data-history="rewrite"]').click();
    await expect(page.locator('#cons-verdict')).toContainText('HISTORY TAMPERING DETECTED');
    await expect(page.locator('#cons-verdict')).toHaveClass(/proof-invalid/);

    // The auditor's old root is untouched — it is the log's replay that fails.
    expect((await page.locator('#cons-oldroot').textContent())!.trim()).toBe(honestOldRoot);
    // At least one side of the replay must be flagged as not reproducing the
    // root it is supposed to. Which side depends on whether the old size is a
    // power of two; the failure is real either way.
    const mismatches = page.locator('[data-rebuilt-match="no"]');
    expect(await mismatches.count()).toBeGreaterThan(0);
    for (const id of ['#cons-rebuilt-old', '#cons-rebuilt-new']) {
      const value = (await page.locator(id).textContent())!.trim();
      expect(value).toMatch(HEX64);
    }
  });

  test('deletion and reordering are caught even though the log still grows', async ({ page }) => {
    await gotoLab(page);

    for (const scenario of ['delete', 'reorder']) {
      await page.locator(`[data-history="${scenario}"]`).click();
      const m = Number(((await page.locator('#cons-m').textContent()) ?? '').replace(/\D/g, ''));
      const n = Number(((await page.locator('#cons-n').textContent()) ?? '').replace(/\D/g, ''));
      expect(n, `${scenario}: the log must still grow`).toBeGreaterThan(m);
      await expect(page.locator('#cons-verdict'), scenario).toContainText(
        'HISTORY TAMPERING DETECTED',
      );
      expect(await page.locator('[data-rebuilt-match="no"]').count(), scenario).toBeGreaterThan(0);
    }

    // Returning to the honest case verifies again — the check is not sticky.
    await page.locator('[data-history="append"]').click();
    await expect(page.locator('#cons-verdict')).toContainText('APPEND-ONLY CONFIRMED');
    await expect(page.locator('[data-rebuilt-match="no"]')).toHaveCount(0);
  });
});

test.describe('core inclusion loop still holds', () => {
  test('a proof verifies and a tampered leaf breaks it', async ({ page }) => {
    await gotoLab(page);

    await page.locator('#generate-proof').click();
    await expect(page.locator('.proof-panel')).toBeVisible();
    await expect(page.locator('.proof-panel')).toContainText('Byte-for-byte identical');

    await page.locator('#tamper-leaf').click();
    await expect(page.locator('.proof-panel')).toContainText('PROOF INVALID');
  });
});

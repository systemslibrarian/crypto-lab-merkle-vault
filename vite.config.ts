/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-merkle-vault/',
  test: {
    globals: true,
    environment: 'node',
    // Playwright specs live in e2e/ and run via `npm run test:a11y`.
    // Keep them out of the vitest (unit) run.
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
  },
});

import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('.', import.meta.url)) } },
  test: {
    include: ['tests/**/*.test.ts'],
    // npm run coverage: how much of the console's library code the tests run. CI fails if it drops below the
    // thresholds, so raise them as tests are added, never lower them to make a change pass.
    coverage: {
      provider: 'v8',
      include: ['lib/**'],
      reporter: ['text', 'text-summary', 'json-summary'],
      thresholds: { lines: 25, statements: 24, branches: 30, functions: 28 },
    },
  },
});

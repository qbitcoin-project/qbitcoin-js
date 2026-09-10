import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/index.ts'],
      thresholds: {
        // Acceptance gate. Money math has no excuses.
        branches: 100,
        functions: 100,
        lines: 100,
        statements: 100,
      },
    },
  },
});

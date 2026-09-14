import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '@qbtc/crypto': new URL('../crypto/src/index.ts', import.meta.url).pathname },
  },
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});

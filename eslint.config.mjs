import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '**/wasm/**', 'tools/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // A leading underscore marks an intentionally-unused binding (a positional
    // argument, a destructured value, or a caught error we don't inspect).
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
    },
  },
)

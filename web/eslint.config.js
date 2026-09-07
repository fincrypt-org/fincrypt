import js from '@eslint/js'
import tseslint from '@typescript-eslint/eslint-plugin'
import tsparser from '@typescript-eslint/parser'
import reactHooks from 'eslint-plugin-react-hooks'

export default [
  {
    ignores: ['dist/', 'node_modules/', 'playwright-report/', 'test-results/'],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        crypto: 'readonly',
        localStorage: 'readonly',
        indexedDB: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      'react-hooks': reactHooks,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
  {
    files: ['*.config.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      globals: { process: 'readonly' },
    },
  },
  {
    // I7 storage ban: no key material may ever touch persistence APIs
    // in the crypto core or the session keystore.
    files: ['src/crypto/**/*.ts', 'src/stores/**/*.ts'],
    ignores: ['src/crypto/**/*.test.ts', 'src/stores/**/*.test.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'I7: keys are never persisted (see API.md)' },
        { name: 'sessionStorage', message: 'I7: keys are never persisted (see sessionKeys.ts)' },
        { name: 'indexedDB', message: 'I7: keys are never persisted (see sessionKeys.ts)' },
        { name: 'caches', message: 'I7: keys are never persisted' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'document', property: 'cookie', message: 'I7: keys are never persisted in cookies' },
      ],
    },
  },
]

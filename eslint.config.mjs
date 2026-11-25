const browserGlobals = [
  'Blob',
  'URL',
  'clearInterval',
  'clearTimeout',
  'confirm',
  'console',
  'document',
  'fetch',
  'Image',
  'URLSearchParams',
  'XMLSerializer',
  'localStorage',
  'location',
  'navigator',
  'setInterval',
  'setTimeout',
  'window',
];

export default [
  {
    files: ['h4k/web/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: Object.fromEntries(browserGlobals.map((name) => [name, 'readonly'])),
    },
    rules: {
      'no-dupe-keys': 'error',
      'no-redeclare': 'error',
      'no-undef': 'error',
      'no-unreachable': 'error',
      'no-unused-vars': ['error', { args: 'none' }],
    },
  },
];

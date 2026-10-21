'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { scanConfig, defaultPaths } = require('../bin/mcpsec.js');

test('devcontainer.json with comments and trailing commas parses and scans', () => {
  const raw = [
    '{',
    '  // devcontainer with comments',
    '  "name": "dev",',
    '  "mcpServers": {',
    '    "supabase": {',
    '      "command": "npx",',
    '      "args": ["-y", "@supabase/mcp-server-supabase"],',
    '      "env": { "SUPABASE_SERVICE_ROLE_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.FAKESIGFAKESIGFAKE", }',
    '    },',
    '  },',
    '}',
  ].join('\n');
  const res = scanConfig('devcontainer.json', raw);
  assert.strictEqual(res.error, undefined);
  assert.ok(res.findings.some((f) => f.rule === 'SERVICE_ROLE_JWT'));
});

test('plain JSON still parses strictly (no comment stripping side effects)', () => {
  const res = scanConfig('c.json', '{"mcpServers": {"x": {"command": "n", "args": ["a//b"]}}}');
  assert.strictEqual(res.error, undefined);
  assert.strictEqual(res.findings.length, 0);
});

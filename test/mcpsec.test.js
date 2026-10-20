'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scanConfig, scanServer, isRealSecretValue, redact } = require('../bin/mcpsec.js');

const ROOT = path.join(__dirname, '..');
const brokenRaw = fs.readFileSync(path.join(ROOT, 'examples', 'broken', 'claude_desktop_config.json'), 'utf8');
const cleanRaw = fs.readFileSync(path.join(ROOT, 'examples', 'clean', 'claude_desktop_config.json'), 'utf8');

test('broken example triggers every expected rule', () => {
  const res = scanConfig('broken.json', brokenRaw);
  assert.strictEqual(res.error, undefined);
  const rules = res.findings.map((f) => f.rule);
  for (const expected of [
    'SERVICE_ROLE_JWT',
    'HARDCODED_SECRET',
    'AUTO_APPROVE_WRITE',
    'SHELL_INTERPOLATION',
    'FS_ROOT_ACCESS',
    'INSECURE_TRANSPORT',
    'TLS_VERIFICATION_DISABLED',
    'PLAINTEXT_PASSWORD',
    'SKIP_PERMISSIONS_FLAG',
  ]) {
    assert.ok(rules.includes(expected), 'missing rule: ' + expected);
  }
  assert.ok(res.findings.some((f) => f.rule === 'SERVICE_ROLE_JWT' && f.severity === 'critical'));
});

test('clean example produces zero findings', () => {
  const res = scanConfig('clean.json', cleanRaw);
  assert.strictEqual(res.error, undefined);
  assert.strictEqual(res.findings.length, 0);
});

test('placeholder values are never reported as secrets', () => {
  assert.strictEqual(isRealSecretValue('${GITHUB_TOKEN}'), false);
  assert.strictEqual(isRealSecretValue('your-key-here-123456'), false);
  assert.strictEqual(isRealSecretValue('ghp_FAKE0000FAKE0000FAKE0000FAKE0000'), true);
});

test('service_role JWT is detected even under a neutral key name', () => {
  const res = scanServer('x', { env: { DATA: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.FAKESIGFAKESIGFAKE' } });
  assert.ok(res.some((f) => f.rule === 'SERVICE_ROLE_JWT' && f.severity === 'critical'));
});

test('non-service_role JWTs are not flagged', () => {
  const res = scanServer('x', { env: { DATA: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.FAKESIGFAKESIGFAKE' } });
  assert.strictEqual(res.length, 0);
});

test('findings never contain the full secret value', () => {
  const res = scanConfig('broken.json', brokenRaw);
  for (const f of res.findings) {
    assert.ok(!f.evidence.includes('FAKE0000FAKE0000FAKE0000FAKE0000'), 'full token leaked in evidence');
  }
});

test('redaction truncates and marks length', () => {
  const r = redact('ghp_FAKE0000FAKE0000FAKE0000FAKE0000');
  assert.ok(r.startsWith('ghp_FA'));
  assert.ok(r.includes('***'));
  assert.ok(r.includes('36 chars'));
});

test('invalid JSON is reported, not thrown', () => {
  const res = scanConfig('bad.json', 'not json at all');
  assert.match(res.error, /not valid JSON/);
  assert.strictEqual(res.findings.length, 0);
});

test('configs without mcpServers are skipped with a reason', () => {
  const res = scanConfig('other.json', '{"foo": 1}');
  assert.match(res.error, /no mcpServers/);
});

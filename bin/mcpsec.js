#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SECRET_NAME_RE = /(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|SERVICE[_-]?ROLE|CREDENTIAL)/i;
const PASSWORD_NAME_RE = /^(.*[-_])?(PASSWORD|PASSWD)([-_].*)?$/i;
const SECRET_VALUE_PATTERNS = [
  /^sk-(ant-)?[A-Za-z0-9_-]{20,}$/,
  /^ghp_[A-Za-z0-9]{30,}$/,
  /^github_pat_[A-Za-z0-9_]{20,}$/,
  /^AKIA[0-9A-Z]{16}$/,
  /^AIza[0-9A-Za-z_-]{30,}$/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/,
  /^glpat-[A-Za-z0-9_-]{15,}$/,
  /^npm_[A-Za-z0-9]{30,}$/,
  /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/,
];
const PLACEHOLDER_RE = /^(\$\{|%|\{|<|your|my[-_]?|change|example|placeholder|xxx|\*|0+|test[-_]?|dummy|fake)/i;
const SKIP_PERMISSION_FLAGS = /--dangerously-skip-permissions|--yolo|--auto-approve/i;
const WRITE_TOOL_RE = /(write|edit|exec|run|eval|delete|insert|update|command|shell|terminal|sql|migration|deploy)/i;
const SHELLS = new Set(['bash', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh']);
const JWT_RE = /^eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*$/;

function b64urlDecode(seg) {
  let s = seg.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  try {
    return JSON.parse(Buffer.from(s, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function redact(value) {
  const v = String(value);
  if (v.length <= 8) return v.slice(0, 2) + '***';
  return v.slice(0, 6) + '***(' + v.length + ' chars)';
}

function isRealSecretValue(value) {
  if (typeof value !== 'string' || value.length < 16) return false;
  if (PLACEHOLDER_RE.test(value)) return false;
  return SECRET_VALUE_PATTERNS.some((re) => re.test(value));
}

function scanJwt(value) {
  if (typeof value !== 'string') return null;
  const m = JWT_RE.exec(value);
  if (!m) return null;
  const payload = b64urlDecode(m[1]);
  if (payload && payload.role === 'service_role') {
    return 'decoded JWT payload has role=service_role';
  }
  return null;
}

function scanKeyValueMap(server, where, map, findings) {
  if (!map || typeof map !== 'object') return;
  for (const [key, value] of Object.entries(map)) {
    if (typeof value !== 'string') continue;
    if (PASSWORD_NAME_RE.test(key) && value.length > 0) {
      findings.push({
        rule: 'PLAINTEXT_PASSWORD', severity: 'high', server,
        detail: where + ' key "' + key + '" holds a plaintext password in the config file',
        evidence: redact(value),
      });
      continue;
    }
    const serviceRole = scanJwt(value);
    if (serviceRole) {
      findings.push({
        rule: 'SERVICE_ROLE_JWT', severity: 'critical', server,
        detail: where + ' key "' + key + '": ' + serviceRole + ' (bypasses all RLS)',
        evidence: redact(value),
      });
      continue;
    }
    if (SECRET_NAME_RE.test(key) && isRealSecretValue(value)) {
      findings.push({
        rule: 'HARDCODED_SECRET', severity: 'critical', server,
        detail: where + ' key "' + key + '" holds a real-looking secret',
        evidence: redact(value),
      });
      continue;
    }
    if (isRealSecretValue(value) && !SECRET_NAME_RE.test(key) && !JWT_RE.test(value)) {
      findings.push({
        rule: 'HARDCODED_SECRET', severity: 'high', server,
        detail: where + ' value under "' + key + '" matches a known secret format but the key name gives it away too',
        evidence: redact(value),
      });
    }
  }
}

function scanServer(server, def) {
  const findings = [];
  if (!def || typeof def !== 'object') return findings;

  scanKeyValueMap(server, 'env', def.env, findings);
  scanKeyValueMap(server, 'headers', def.headers, findings);

  if (typeof def.url === 'string' && /^http:\/\//i.test(def.url)) {
    let host = '';
    try { host = new URL(def.url).hostname; } catch { host = ''; }
    if (!['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)) {
      findings.push({
        rule: 'INSECURE_TRANSPORT', severity: 'high', server,
        detail: 'server URL uses plaintext http:// outside localhost',
        evidence: def.url,
      });
    }
  }

  const args = Array.isArray(def.args) ? def.args.map(String) : [];
  if (args.some((a) => SKIP_PERMISSION_FLAGS.test(a))) {
    findings.push({
      rule: 'SKIP_PERMISSIONS_FLAG', severity: 'high', server,
      detail: 'server launched with a flag that skips the permission prompt entirely',
      evidence: args.join(' ').slice(0, 120),
    });
  }

  if (SHELLS.has(String(def.command || '').toLowerCase())) {
    const joined = args.join(' ');
    const interp = /-c\b|\/c\b|-Command/i.test(joined) && /\$\{|`|%\{/.test(joined);
    if (interp) {
      findings.push({
        rule: 'SHELL_INTERPOLATION', severity: 'high', server,
        detail: 'shell one-liner with variable interpolation: config (or its env) becomes executable code',
        evidence: joined.slice(0, 120),
      });
    }
  }

  const approveKey = ['autoApprove', 'alwaysAllow'].find((k) => Array.isArray(def[k]));
  if (approveKey) {
    const tools = def[approveKey].map(String);
    const writey = tools.filter((t) => WRITE_TOOL_RE.test(t));
    if (writey.length > 0) {
      findings.push({
        rule: 'AUTO_APPROVE_WRITE', severity: 'high', server,
        detail: approveKey + ' silently approves write/execute tools without a human prompt: ' + writey.join(', '),
        evidence: tools.slice(0, 6).join(', '),
      });
    } else if (tools.length > 0) {
      findings.push({
        rule: 'AUTO_APPROVE_TOOLS', severity: 'medium', server,
        detail: approveKey + ' auto-approves ' + tools.length + ' tool calls without confirmation',
        evidence: tools.slice(0, 6).join(', '),
      });
    }
  }

  const isFs = /filesystem/i.test(String(def.command || '') + ' ' + server + ' ' + args.join(' '));
  if (isFs) {
    const roots = args.filter((a) => a === '/' || /^[A-Za-z]:\\?$/.test(a) || a === '~');
    if (roots.length > 0) {
      findings.push({
        rule: 'FS_ROOT_ACCESS', severity: 'medium', server,
        detail: 'filesystem server is rooted at the entire drive/home instead of a project folder',
        evidence: roots.join(' '),
      });
    }
  }

  if (String(def.env && def.env.NODE_TLS_REJECT_UNAUTHORIZED) === '0') {
    findings.push({
      rule: 'TLS_VERIFICATION_DISABLED', severity: 'high', server,
      detail: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification for every request in that process',
      evidence: 'NODE_TLS_REJECT_UNAUTHORIZED=0',
    });
  }

  return findings;
}

const SERVER_KEYS = ['mcpServers', 'servers'];

function tolerantParse(raw) {
  const stripped = String(raw)
    .replace(/^\uFEFF/, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|\s)\/\/[^\n]*/g, (m, p1) => p1)
    .replace(/,\s*([}\]])/g, '$1');
  return JSON.parse(stripped);
}

function scanConfig(filePath, raw) {
  let config;
  const cleaned = String(raw).replace(/^\uFEFF/, '');
  try {
    config = JSON.parse(cleaned);
  } catch (e) {
    try {
      config = tolerantParse(cleaned);
    } catch (e2) {
      return { file: filePath, error: 'not valid JSON: ' + e.message, findings: [] };
    }
  }
  let serverMap = null;
  for (const key of SERVER_KEYS) {
    if (config && typeof config === 'object' && config[key] && typeof config[key] === 'object') {
      serverMap = config[key];
      break;
    }
  }
  if (!serverMap && config && typeof config === 'object') {
    const looksLikeServers = Object.values(config).filter(
      (v) => v && typeof v === 'object' && (v.command || v.url)
    );
    if (looksLikeServers.length > 0) serverMap = config;
  }
  if (!serverMap) {
    return { file: filePath, error: 'no mcpServers/servers object found', findings: [] };
  }
  const findings = [];
  for (const [name, def] of Object.entries(serverMap)) {
    findings.push(...scanServer(name, def));
  }
  return { file: filePath, findings };
}

function defaultPaths() {
  const home = os.homedir();
  const candidates = [
    path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.claude.json'),
    path.join(home, '.mcp.json'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    path.join(home, '.vscode', 'mcp.json'),
    path.join(process.cwd(), '.mcp.json'),
    path.join(process.cwd(), '.vscode', 'mcp.json'),
    path.join(process.cwd(), '.devcontainer', 'devcontainer.json'),
    path.join(process.cwd(), 'devcontainer.json'),
  ];
  return [...new Set(candidates)].filter((p) => fs.existsSync(p));
}

function rank(a, b) {
  return (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
}

function printReport(results) {
  const lines = [];
  let counts = { critical: 0, high: 0, medium: 0 };
  for (const res of results) {
    lines.push('');
    lines.push('== ' + res.file);
    if (res.error) lines.push('   skipped: ' + res.error);
    for (const f of [...res.findings].sort(rank)) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      lines.push('   [' + f.severity.toUpperCase() + '] ' + f.rule + ' - ' + f.server);
      lines.push('       ' + f.detail);
      lines.push('       evidence: ' + f.evidence);
    }
  }
  return { text: lines.join('\n'), counts };
}

function main(argv) {
  const json = argv.includes('--json');
  const paths = argv.filter((a) => !a.startsWith('--'));
  const targets = paths.length > 0 ? paths : defaultPaths();
  if (targets.length === 0) {
    console.error('No MCP config files found. Pass file paths explicitly, e.g.: mcp-security-audit claude_desktop_config.json');
    return 2;
  }
  const results = [];
  for (const file of targets) {
    let raw = '';
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch (e) {
      results.push({ file, error: 'unreadable: ' + e.message, findings: [] });
      continue;
    }
    results.push(scanConfig(file, raw));
  }
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    const { text, counts } = printReport(results);
    console.log(text);
    console.log('');
    console.log('Summary: ' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium');
  }
  const blocking = results.some((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high'));
  return blocking ? 1 : 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { scanConfig, scanServer, isRealSecretValue, redact, defaultPaths, main, scanJwt, b64urlDecode, JWT_RE };

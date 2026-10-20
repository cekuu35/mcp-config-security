# mcp-security-audit

Scan MCP (Model Context Protocol) client configuration files for leaked
credentials and unsafe settings — before an agent process runs with them.

MCP configs are a new class of secret store: every server entry can carry a
literal `env` block, auth headers, and flags that silently disable permission
prompts. Most people paste tokens straight into `claude_desktop_config.json`
or `.mcp.json` and never look again. This tool reads those files locally and
reports what would hurt if the file (or your machine) leaked.

Zero dependencies. Reads nothing from the network. Never sends your config
anywhere.

## Quick start

```bash
git clone https://github.com/cekuu35/mcp-security-audit
cd mcp-security-audit
node bin/mcpsec.js                 # scans default client config locations
node bin/mcpsec.js path/to/config.json --json
```

Default locations scanned: Claude Desktop, Claude Code (`.claude.json`),
`.mcp.json` (project + home), Cursor, Windsurf. Pass explicit paths for
anything else.

Exit codes are CI-friendly: `0` clean, `1` any critical/high finding, `2` no
config files found.

## What it detects

| Rule | Severity | What it catches |
|---|---|---|
| `SERVICE_ROLE_JWT` | critical | a JWT whose decoded payload has `role=service_role` — under any key name, bypasses all RLS |
| `HARDCODED_SECRET` | critical/high | real-looking tokens in `env`/`headers`: OpenAI/Anthropic `sk-`, GitHub `ghp_`/PAT, AWS `AKIA`, Google `AIza`, Slack `xox`, GitLab `glpat`, npm |
| `PLAINTEXT_PASSWORD` | high | any `*PASSWORD*` key with a literal value |
| `SKIP_PERMISSIONS_FLAG` | high | `--dangerously-skip-permissions`, `--yolo`, `--auto-approve` in args |
| `AUTO_APPROVE_WRITE` | high | `autoApprove`/`alwaysAllow` silently approving write/execute tools (e.g. `execute_sql`) |
| `INSECURE_TRANSPORT` | high | remote servers over plain `http://` outside localhost |
| `TLS_VERIFICATION_DISABLED` | high | `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| `SHELL_INTERPOLATION` | high | `bash -c "… ${VAR} …"` style one-liners where the config becomes executable code |
| `AUTO_APPROVE_TOOLS` | medium | auto-approval of non-write tools without confirmation |
| `FS_ROOT_ACCESS` | medium | filesystem servers rooted at `/`, `C:\` or `~` instead of a project folder |

Placeholder values (`${GITHUB_TOKEN}`, `your-key-here`) are never reported.
JWT payloads are actually decoded — not pattern-matched — so a
service-role token hiding under a neutral key name is still caught.

## Example output

Scanning the [broken example config](examples/broken/claude_desktop_config.json):

```
== examples/broken/claude_desktop_config.json
   [CRITICAL] SERVICE_ROLE_JWT - supabase
       env key "SUPABASE_SERVICE_ROLE_KEY": decoded JWT payload has role=service_role (bypasses all RLS)
       evidence: eyJhbG***(87 chars)
   [HIGH] AUTO_APPROVE_WRITE - supabase-admin
       autoApprove silently approves write/execute tools without a human prompt: execute_sql, apply_migration
       evidence: execute_sql, apply_migration
   ...

Summary: 2 critical, 6 high, 1 medium
```

All example values are synthetic. Evidence in reports is always redacted —
the full secret value never appears in output, so the report itself is safe
to paste into an issue or a ticket.

## Tests

```bash
npm test
```

9 tests, zero dependencies (Node's built-in test runner): every rule fires on
the broken fixture, the clean fixture stays clean, placeholders are ignored,
non-service_role JWTs are not flagged, redaction never leaks the full value.

## Honest scope

This is a configuration review tool, not a penetration test or a security
guarantee. It reads client-side MCP configs; it does not audit the servers
those configs launch, their tool implementations, or what they do at runtime.
Clean output means the config file itself holds nothing dangerous — not that
your agent stack is secure.

I run this against my own machine's configs; on my Windows setup it found two
live config files (Claude Code, Cursor) and came back clean, because mine
reference environment variables instead of literal values. That is the
correct answer here — a clean result should be boring.

## Related

- [supabase-rls-leak-demo](https://github.com/cekuu35/supabase-rls-leak-demo) — the same red/green approach for Supabase row-level security leaks
- [Supabase RLS Audit Kit](https://cengokurtoglu.gumroad.com/l/supabase-rls-audit-kit?utm_source=github_repo&utm_medium=readme&utm_campaign=mcp_audit) — if the leaked key was a Supabase service_role, run the full audit against your database
- [Hire me for a Supabase security audit (Upwork, from $99)](https://www.upwork.com/services/product/2083862107074689176?utm_source=github_repo&utm_medium=readme&utm_campaign=mcp_audit)

## License

MIT

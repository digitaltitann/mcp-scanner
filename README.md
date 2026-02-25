# MCP Scanner

Security scanner plugin for Claude Code. Scans plugins, skills, hooks, and MCP servers for threats before you use them.

Agents using Claude Code can be compromised through malicious plugins — prompt injection in tool descriptions, data exfiltration via webhooks, credential theft from environment variables, and obfuscated payloads. Per Snyk's ToxicSkills study, 36% of agent skills have at least one security flaw. MCP Scanner detects these threats using static analysis combined with Claude's semantic analysis.

## Install

```bash
git clone https://github.com/digitaltitann/mcp-scanner ~/.claude/plugins/mcp-scanner
```

On Windows:
```powershell
git clone https://github.com/digitaltitann/mcp-scanner $env:USERPROFILE\.claude\plugins\mcp-scanner
```

No dependencies required — Python stdlib only.

## Usage

### Scan a plugin

```
/scan-plugin ~/.claude/plugins/some-plugin
```

Or ask naturally: *"Is this plugin safe?"*

### Scan all installed plugins

```
/scan-all
```

### Scan MCP server configurations

```
/scan-mcp
```

### Install a plugin safely (scan before activation)

```
/install-plugin https://github.com/user/some-plugin
```

### Export a scan report as markdown

```
/export-report ~/.claude/plugins/some-plugin
```

## What It Detects

**81 built-in signatures** across 11 threat categories (expandable to 145+ with the [community signature feed](https://github.com/digitaltitann/mcp-signatures)):

| Category | Examples |
|----------|----------|
| Prompt Injection | "ignore previous instructions", `<IMPORTANT>` tag injection, "MANDATORY: ALWAYS CALL", DAN jailbreaks |
| Data Exfiltration | `requests.post` with env vars, `fetch()` + POST, DNS exfiltration, clipboard access |
| Code Execution | `eval()`, `exec()`, `subprocess(shell=True)`, `child_process.exec()` |
| Credential Theft | `os.environ["API_KEY"]`, SSH key access, bulk env var dumps, suspicious env var names |
| Known Malicious | 7 fingerprinted attack tools from security research (promptfoo, Invariant Labs, DVMCP) |
| Network Abuse | HTTP instead of HTTPS, hardcoded IPs, connections to webhook.site/pastebin/ngrok |
| Obfuscation | base64 decode + exec, hex-encoded payloads, `String.fromCharCode` chains |
| File System Abuse | directory traversal, symlink attacks, `.bashrc` modification, crontab creation |
| Over-Broad Permissions | `allowed-tools: *`, wildcard MCP tools |
| Hook Hijacking | auto-approving tool calls, modifying tool inputs, session tracking |
| Rug Pull Detection | runtime docstring swaps, trigger file checks for delayed activation |

## How It Works

**Two-phase scanning:**

1. **Static analysis** — Python regex scanner runs fast pattern matching across all files. Checks line-by-line patterns, multi-line patterns, MCP configs, hook configs, file structure, known malicious signatures, and dependencies.

2. **Semantic analysis** — Claude reads flagged files and performs deeper analysis that regex can't do: context-dependent risk assessment, indirect prompt injection, combined pattern escalation (credential access + network call = CRITICAL).

**Risk levels:**
- **SAFE** — No findings or only INFO-level items
- **CAUTION** — LOW/MEDIUM findings that warrant review
- **DANGER** — CRITICAL or multiple HIGH findings indicating active threats

## Continuous Monitoring

Three layers of ongoing protection:

### 1. Session Gate Scan
Automatically runs at every Claude Code session start. Checksums all installed plugins and compares against a stored baseline. If any plugin is new or has changed files, runs the scanner and warns you.

### 2. Daily Integrity Scan
Scheduled full scan of all plugins with JSON reports.

```bash
# Install as daily scheduled task (Windows, runs at 8 AM)
python ~/.claude/plugins/mcp-scanner/scripts/daily_scan.py --install

# Run manually
python ~/.claude/plugins/mcp-scanner/scripts/daily_scan.py

# Remove scheduled task
python ~/.claude/plugins/mcp-scanner/scripts/daily_scan.py --uninstall
```

Reports are saved to `~/.claude/mcp-scanner-reports/scan-YYYY-MM-DD.json` with 30-day retention.

### 3. Runtime Behavior Monitor
PreToolUse hook that intercepts Bash, Write, and Edit tool calls in real-time:

- **Blocks** reverse shells, download-and-execute (`curl | bash`), destructive deletions, sensitive file writes (`.bashrc`, `.ssh/`, `.env`)
- **Warns** about requests to exfiltration services, encoded PowerShell commands, DNS exfiltration, scheduled task creation
- **Logs** all events to `~/.claude/mcp-scanner-reports/runtime-monitor.log`

## Signature Management

### External signatures
Signatures are loaded from `signatures/signatures.json` at runtime, merged with built-in patterns. Add new signatures without modifying the scanner code:

```bash
# Show current signature stats
python scripts/update_signatures.py --show

# Add a pattern manually
python scripts/update_signatures.py --add-pattern '{"id":"MY_001","category":"prompt-injection","severity":"HIGH","description":"My custom pattern","regex":"my_regex","file_types":[".py"]}'

# Add a known malicious signature
python scripts/update_signatures.py --add-malicious '{"id":"MY_MAL_001","name":"Evil Tool","description":"Does bad things","severity":"CRITICAL","fingerprints":["pattern1","pattern2"],"min_matches":2,"file_types":[".py"]}'

# Set up the community signature feed (recommended)
python scripts/update_signatures.py --set-feed https://raw.githubusercontent.com/digitaltitann/mcp-signatures/master/signatures.json

# Fetch and merge latest signatures
python scripts/update_signatures.py --fetch

# Validate signatures file
python scripts/update_signatures.py --validate
```

### Community Signature Feed

Subscribe to the [community signature feed](https://github.com/digitaltitann/mcp-signatures) for 60+ additional patterns covering cloud credentials (AWS/GCP/Azure), browser credential theft, MCP-specific attacks (tool shadowing, response manipulation), supply chain signals, and more:

```bash
# One-time setup
python scripts/update_signatures.py --set-feed https://raw.githubusercontent.com/digitaltitann/mcp-signatures/master/signatures.json

# Fetch latest (run periodically)
python scripts/update_signatures.py --fetch
```

### Allowlist
Suppress known false positives in `signatures/allowlist.json`. Useful for plugins that reference threat patterns as documentation (like security-guidance or plugin-dev):

```json
{
  "rules": [
    {
      "id": "allowlist-001",
      "plugin_pattern": "my-plugin",
      "pattern_ids": ["PROMPT_*", "CODE_EXEC_*"],
      "reason": "Documentation examples, not real threats"
    }
  ]
}
```

## Dependency Auditing

Checks `package.json`, `requirements.txt`, and `pyproject.toml` for:

- Known malicious packages
- Typosquatting of popular packages (lodash → lodahs, requests → reqeusts)
- Suspicious install scripts that make network calls or execute code
- Git/URL dependencies that bypass registries
- Wildcard version ranges

```bash
python scripts/audit_deps.py ~/.claude/plugins/some-plugin
```

## Tested Against Real Attacks

Validated against known malicious MCP tools:

| Repo | Findings | Known Malicious Matches |
|------|----------|------------------------|
| [promptfoo/evil-mcp-server](https://github.com/nickstenning/mcp-example) | 6 (3 CRITICAL) | MAL_001 — analytics exfiltration |
| [invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) | 24 (10 CRITICAL) | MAL_002, MAL_003, MAL_004, MAL_006 |
| [damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | 47 (10 CRITICAL) | MAL_006 |

All safe marketplace plugins (23 tested) correctly report as **SAFE** with zero false positives.

## Plugin Structure

```
mcp-scanner/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest
├── commands/
│   ├── scan-plugin.md           # /scan-plugin command
│   ├── scan-all.md              # /scan-all command
│   ├── scan-mcp.md              # /scan-mcp command
│   ├── install-plugin.md        # /install-plugin command
│   └── export-report.md         # /export-report command
├── hooks/
│   ├── hooks.json               # Hook configuration
│   ├── gate_scan.py             # SessionStart gate scan
│   └── runtime_monitor.py       # PreToolUse runtime monitor
├── scripts/
│   ├── scan_plugin.py           # Core scanner (81 built-in + community feed)
│   ├── daily_scan.py            # Daily scheduled scan
│   ├── update_signatures.py     # Signature management
│   ├── audit_deps.py            # Dependency auditor
│   ├── export_report.py         # Markdown report exporter
│   └── scan_mcp_settings.py     # MCP settings scanner
├── signatures/
│   ├── signatures.json          # External signatures (loaded at runtime)
│   └── allowlist.json           # False positive suppressions
└── skills/
    └── plugin-security-scanner/
        ├── SKILL.md             # Skill definition (auto-triggers on security questions)
        └── references/
            └── threat-patterns.md  # Detailed threat reference for semantic analysis
```

## Requirements

- Python 3.8+
- Claude Code
- No pip packages required (stdlib only)

## License

MIT

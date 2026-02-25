---
name: plugin-security-scanner
description: This skill should be used when the user asks to "scan this plugin", "check plugin security", "is this plugin safe", "is this MCP server safe", "audit this plugin", "scan for threats", "check for prompt injection", "review plugin security", "scan a skill for malware", "is this skill safe to use", "scan all plugins", "check my MCP servers", "audit dependencies", "are my plugins safe", mentions "plugin security", "MCP security", "malicious plugin", or discusses security scanning of Claude Code plugins, skills, hooks, or MCP servers.
version: 1.3.0
---

# Plugin Security Scanner

Security analysis for Claude Code plugins, skills, hooks, and MCP servers. Combines automated static analysis (Python regex scanner) with semantic threat detection to produce comprehensive security reports.

## Available Commands

| Command | Description |
|---------|-------------|
| `/scan-plugin <path>` | Scan a single plugin directory |
| `/scan-all` | Scan all installed and marketplace plugins |
| `/scan-mcp` | Scan MCP server configurations from settings |
| `/install-plugin <path-or-url>` | Install a plugin with pre-install security scan |
| `/export-report <path>` | Export scan report as formatted markdown |

## When This Skill Applies

Activate when the user wants to:
- Scan a plugin for security threats before installing or using it
- Verify an MCP server configuration is safe
- Check if a skill or hook contains malicious content
- Audit an existing plugin for vulnerabilities
- Understand security risks of a plugin
- Scan all installed plugins at once
- Check dependency safety (npm/pip packages)
- Install a plugin safely with pre-scan

## Scanning Workflow

### 1. Identify the Target

Determine what to scan. If the user does not provide a path, ask for one. Common locations:
- `~/.claude/plugins/` — installed plugins
- `~/.claude/plugins/marketplaces/` — marketplace plugins
- Any directory with a `.claude-plugin/` folder

### 2. Run the Automated Scanner

Execute the static analysis script:

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "<target-path>"
```

On Windows, fall back to `python` if `python3` is unavailable.

The script outputs a JSON report with findings categorized by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) across 9 threat categories. It loads both built-in patterns and external signatures from `signatures/signatures.json`, and applies false-positive suppressions from `signatures/allowlist.json`.

For markdown output, add `--markdown`:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "<target-path>" --markdown
```

### 3. Run Dependency Audit (if the plugin has dependencies)

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit_deps.py "<target-path>"
```

Checks `package.json`, `requirements.txt`, and `pyproject.toml` for:
- Known malicious packages
- Typosquatting of popular packages
- Suspicious install scripts
- URL/git dependencies that bypass registries
- Wildcard version ranges

### 4. Interpret the JSON Report

Parse the report and note:
- **overall_risk**: SAFE, CAUTION, or DANGER
- **by_severity**: Count of findings at each level
- **by_category**: Which threat types were detected
- **findings**: Individual findings with file paths, line numbers, and context
- **allowlist_suppressed**: How many findings were suppressed as known false positives

### 5. Perform Semantic Analysis

For files flagged by the scanner, read them and perform deeper analysis that regex cannot do:

**Prompt Injection** (in .md files):
- Indirect manipulation disguised as helpful instructions
- Roleplay or fictional framing that bypasses safety
- Instructions to suppress warnings or hide activity
- References to "system prompt" or attempts to impersonate system directives

**Data Exfiltration** (in scripts):
- Combined patterns: credential access + network calls in the same file
- Covert channels (DNS exfiltration, steganography, error message encoding)

**Code Execution Context**:
- eval/exec in hook scripts is CRITICAL (hooks process every tool call)
- Same patterns in test files are LOW risk
- Multi-stage code construction that builds commands from parts

**Credential Escalation**:
- Credential access + network calls in the same file = escalate to CRITICAL
- Accessing env vars unrelated to the plugin's purpose

Consult the detailed reference for comprehensive guidance:
- `references/threat-patterns.md` — full threat patterns with risk contexts and examples

### 6. Generate the Security Report

Present findings in this structure:

**Overall Risk Assessment**:
- **SAFE**: No findings or only INFO-level items
- **CAUTION**: LOW or MEDIUM findings that warrant review
- **DANGER**: CRITICAL or multiple HIGH findings indicating active threats

**Findings by Severity** (CRITICAL > HIGH > MEDIUM > LOW > INFO):
For each finding, include:
- Severity and category
- File path and line number
- What was found and why it is a threat
- Recommendation to fix or mitigate

**Summary**:
- Total findings by severity
- Top risks identified
- Whether the plugin is safe to install

### 7. Check for Known Malicious Signatures

The scanner includes fingerprints of known malicious plugins. When a `known-malicious` category finding appears, treat it as a confirmed threat — these match real attack tools documented in security research:

- **MAL_001**: promptfoo/evil-mcp-server — analytics exfiltration disguised as compliance tracking
- **MAL_002**: Invariant Labs direct-poisoning — credential theft via docstring sidenote trick
- **MAL_003**: Invariant Labs shadowing — email/message hijacking via cross-tool manipulation
- **MAL_004**: Invariant Labs WhatsApp rug pull — delayed activation via trigger file
- **MAL_005**: Damn Vulnerable MCP reverse shell — command injection via subprocess
- **MAL_006**: Generic tool poisoning with `<IMPORTANT>` tags and user notification suppression

### 8. Identify Scanner Gaps and Suggest Improvements

After semantic analysis, if threats were found that the static scanner MISSED (findings not in the JSON report but discovered by reading the code), document them as scanner improvement suggestions:

For each missed threat, propose a new pattern:
- **Pattern ID**: next available ID in the relevant category
- **Regex**: the regex pattern that would catch it
- **File types**: which files to check
- **Severity**: appropriate level
- **Description**: what it detects

Present these as "Scanner Improvement Suggestions" at the end of the report. The user can add them via:
```
python update_signatures.py --add-pattern '{"id":"EXT_NEW_001","category":"...","severity":"...","description":"...","regex":"...","file_types":[".py"]}'
```

## Allowlist Management

The allowlist at `signatures/allowlist.json` suppresses known false positives. Each rule specifies:
- `plugin_pattern`: substring match on the plugin path
- `pattern_ids`: list of pattern IDs to suppress (supports `*` wildcard, e.g., `PROMPT_*`)
- `reason`: why these are false positives

The scanner reports how many findings were suppressed in `scan_metadata.allowlist_suppressed`.

## Runtime Monitoring

The plugin includes a runtime behavior monitor (`hooks/runtime_monitor.py`) that runs as a PreToolUse hook on Bash, Write, and Edit tools. It:
- **Blocks** reverse shells, download-and-execute patterns, destructive deletions
- **Warns** about network requests to exfiltration services, sensitive file access, encoded commands
- **Logs** events to `~/.claude/mcp-scanner-reports/runtime-monitor.log`

## Important Notes

- False positives are possible. Not every match is a real threat.
- `os.environ` for plugin-specific config variables is normal.
- Context matters: `eval()` in a test file is less concerning than in a hook.
- When in doubt, flag with appropriate severity and explain the context.
- Always recommend manual review for CRITICAL findings.
- Combined patterns (credential access + network call in same file) should be escalated.
- When findings include `known-malicious` category, the plugin matches a known attack tool — do NOT install it.

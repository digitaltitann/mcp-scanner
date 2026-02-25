---
description: Scan a plugin or MCP server for security threats
argument-hint: <path-to-plugin>
allowed-tools: [Read, Glob, Grep, Bash]
---

# Security Scan: Plugin Threat Analysis

Perform a security scan on a Claude Code plugin to identify potential threats before the plugin is used.

## Target

Path: $ARGUMENTS

If no path was provided, ask the user for the path to the plugin directory to scan.

## Step 1: Run Static Analysis

Run the automated scanner to get an initial report:

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "$ARGUMENTS"
```

If `python3` is not found, use `python` instead.

## Step 2: Parse the Report

The scanner outputs JSON. Extract:
- `summary.overall_risk` — SAFE, CAUTION, or DANGER
- `summary.total_findings` — total number of issues found
- `summary.by_severity` — breakdown by CRITICAL/HIGH/MEDIUM/LOW/INFO
- `findings` — array of individual findings with file paths and line numbers

## Step 3: Semantic Analysis

For each file with HIGH or CRITICAL findings, read the file and perform deeper analysis.

Focus on threats regex cannot catch:
1. **Prompt injection**: Indirect manipulation disguised as helpful instructions, roleplay hijacking, suppression of warnings
2. **Combined patterns**: Credential access + network calls in the same file (escalate to CRITICAL)
3. **Hook hijacking**: Hooks that modify tool inputs with broad matchers, auto-approve tool calls, or exfiltrate tool data
4. **MCP safety**: Verify URLs use HTTPS, credentials use env var references, domains are legitimate

Read the threat patterns reference for detailed guidance:
`${CLAUDE_PLUGIN_ROOT}/skills/plugin-security-scanner/references/threat-patterns.md`

## Step 4: Present the Security Report

Format the final report:

### Overall Risk: [SAFE | CAUTION | DANGER]

### Findings

Group by severity (CRITICAL first). For each:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category**: prompt-injection / data-exfiltration / code-execution / credential-theft / network-abuse / obfuscation / filesystem-abuse / over-broad-permissions / hook-hijacking
- **Location**: file path : line number
- **Finding**: what was detected
- **Risk**: why it matters
- **Recommendation**: how to fix or mitigate

### Summary

- Total findings by severity
- Top risks
- Final recommendation: whether this plugin is safe to install and use

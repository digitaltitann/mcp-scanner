---
name: scan-all
description: Scan all installed plugins and marketplace plugins for security threats
---

# Scan All Plugins

Run the MCP Scanner against every installed plugin and produce a consolidated security report.

## Workflow

### 1. Find All Plugins

Search for plugin directories (those containing `.claude-plugin/`) in:
- `~/.claude/plugins/` (installed plugins)
- `~/.claude/plugins/marketplaces/` (marketplace plugins)

Skip the `mcp-scanner` plugin itself to avoid self-referential noise.

### 2. Run the Scanner on Each Plugin

For each plugin found, run:

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "<plugin-path>"
```

On Windows, fall back to `python` if `python3` is unavailable.

Collect the JSON output from each scan.

### 3. Present Summary Dashboard

Create a summary table sorted by risk level (DANGER first):

| Plugin | Risk | Findings | Critical | High | Medium | Low |
|--------|------|----------|----------|------|--------|-----|

### 4. Show Details for Flagged Plugins

For each plugin rated CAUTION or DANGER:
- List the top findings by severity
- Note the file paths and line numbers
- For DANGER plugins with `known-malicious` category findings, prominently warn

### 5. Show Totals

At the end, display:
- Total plugins scanned
- Count by risk level (SAFE / CAUTION / DANGER)
- Total findings across all plugins by severity
- Whether any known malicious signatures matched

### 6. Recommendations

- For DANGER plugins: recommend immediate removal or investigation
- For CAUTION plugins: recommend manual review of flagged files
- If all SAFE: confirm the plugin ecosystem is clean

## Notes

- The mcp-scanner plugin itself is excluded from scanning to avoid false positives from its own pattern definitions
- Scanning many plugins may take a moment — run each scan and report progress as you go
- If a scan fails for a plugin, report the error and continue with the next one

---
name: export-report
description: Export a plugin security scan report as formatted markdown
args: path
---

# Export Security Report

Run the security scanner and export the results as a formatted markdown report.

## Arguments

`$ARGUMENTS` — path to the plugin directory to scan

## Workflow

### 1. Run the Scanner

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "$ARGUMENTS"
```

### 2. Export as Markdown

Pipe the JSON output to the report exporter:

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "$ARGUMENTS" | python ${CLAUDE_PLUGIN_ROOT}/scripts/export_report.py
```

Or generate markdown directly:

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "$ARGUMENTS" --markdown
```

### 3. Present the Report

Display the formatted markdown report to the user. The report includes:
- Header with scan metadata (target, timestamp, scanner version, signature counts)
- Overall risk assessment badge
- Summary statistics table
- Findings organized by severity (CRITICAL first)
- Each finding with file path, line number, description, and context
- Recommendations section

### 4. Optionally Save to File

Ask the user if they want to save the report to a file. If yes, write it to:
- A user-specified path, or
- Default: `~/.claude/mcp-scanner-reports/<plugin-name>-report.md`

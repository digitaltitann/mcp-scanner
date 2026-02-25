---
name: export-sarif
description: Export a plugin scan report in SARIF 2.1.0 format for CI/IDE integration
argument-hint: <path-to-plugin> [-o <output-file>]
allowed-tools: [Read, Bash, Write]
---

# SARIF Export: CI/IDE Integration

Run a security scan and export the results in SARIF 2.1.0 format (Static Analysis Results Interchange Format). SARIF integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security platforms.

## Arguments

`$ARGUMENTS` — path to the plugin directory to scan, optionally followed by `-o <output-file>` to write to a file instead of stdout.

If no path was provided, ask the user for the plugin path.

## Workflow

### 1. Run the Scanner and Export as SARIF

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "$ARGUMENTS" | python ${CLAUDE_PLUGIN_ROOT}/scripts/export_sarif.py
```

To save directly to a file:
```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "<plugin-path>" | python ${CLAUDE_PLUGIN_ROOT}/scripts/export_sarif.py -o <output-file>
```

If `python` is not found, try `python3` instead.

Parse the `$ARGUMENTS` to separate the plugin path from any `-o` flag.

### 2. Handle the Output

**If `-o` was specified:**
- Confirm the SARIF file was written to the specified path
- Report the number of results and rules in the SARIF output

**If no `-o` flag:**
- Display a summary of the SARIF contents (number of rules, results, severity breakdown)
- Ask the user if they want to save it to a file
- Default location: `~/.claude/mcp-scanner-reports/<plugin-name>.sarif`

### 3. Present a Summary

Even when exporting, show a brief summary:
- **Rules defined:** count of unique pattern IDs
- **Results:** total findings
- **By level:** error (CRITICAL/HIGH), warning (MEDIUM), note (LOW/INFO)
- **Overall risk:** from the invocation properties

### 4. Integration Tips

Mention how to use the SARIF output:
- **GitHub Code Scanning:** upload via `gh api` or GitHub Actions with `github/codeql-action/upload-sarif`
- **VS Code:** install the SARIF Viewer extension, then open the `.sarif` file
- **CI pipelines:** fail the build if any `error`-level results are present

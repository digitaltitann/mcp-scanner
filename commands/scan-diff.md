---
name: scan-diff
description: Scan only changed files in a plugin for new security threats
argument-hint: <path-to-plugin> [--since <ref>]
allowed-tools: [Read, Glob, Grep, Bash]
---

# Diff Scanner: Scan Changed Files Only

Run a security scan targeting only files that have changed since the last scan or a given git reference. Highlights NEW threats introduced by recent modifications.

## Arguments

`$ARGUMENTS` — path to the plugin directory, optionally followed by `--since <ref>` (e.g., `HEAD~1`, `2026-02-01`, a commit hash)

If no path was provided, ask the user for the path to the plugin directory to scan.

## Workflow

### 1. Run the Diff Scanner

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_diff.py $ARGUMENTS
```

If `python` is not found, try `python3` instead.

### 2. Parse the JSON Output

The scanner outputs JSON with:
- `diff_summary` — number of changed files, detection method (git or checksum)
- `summary` — overall risk for the changed files only, findings by severity and category
- `findings` — only findings in changed files (each tagged with `diff_status: CHANGED`)

### 3. Handle No Changes

If `diff_summary.status` is `NO_CHANGES`, report:
- "No files have changed since the last scan. The plugin is unchanged."

### 4. Present the Diff Report

**Changed Files:**
List the files that were modified or added.

**New Threats in Changed Files:**
Group findings by severity (CRITICAL first). For each:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category**: the threat category
- **Location**: file path : line number
- **Finding**: what was detected
- **Risk**: why it matters

**Context:**
- Note how many total findings exist in the full plugin vs how many are in the changed files
- This helps the user understand if the changes made things worse

### 5. Recommendations

- If new CRITICAL/HIGH findings appeared in changed files, recommend reverting or fixing before use
- If only LOW/INFO findings, note that the changes appear low-risk
- If no findings in changed files, confirm the changes are clean

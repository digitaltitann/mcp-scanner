---
name: scan-history
description: View scan history, trends, and risk changes for scanned plugins
argument-hint: [--show [name] | --trends | --stats | --export | --prune <days>]
allowed-tools: [Read, Bash]
---

# Scan History: Track Security Over Time

View the scan history database to see how plugin security has changed over time, detect risk regressions, and export historical data.

## Arguments

`$ARGUMENTS` — one of the following subcommands:
- `--show [plugin-name]` — show recent scan history (optionally filtered by plugin name)
- `--show-all` — show all scan history
- `--trends` — show plugins whose risk level changed between scans
- `--stats` — show overall statistics (total scans, unique plugins, risk distribution)
- `--export` — export all history as JSON
- `--prune <days>` — delete entries older than N days (default: 90)

If no arguments provided, default to `--show` to display recent history.

## Workflow

### 1. Run the History Command

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_history.py $ARGUMENTS
```

If `python` is not found, try `python3` instead.

### 2. Present the Results

**For `--show` / `--show-all`:**
Display the history table with columns: Timestamp, Plugin, Risk, Findings, CRIT, HIGH, MED, Sigs.

**For `--trends`:**
Highlight risk changes:
- `!!!` prefix = DEGRADED (risk went up, e.g., SAFE → CAUTION)
- `+++` prefix = IMPROVED (risk went down, e.g., DANGER → SAFE)

Emphasize any degradations — these mean a plugin update introduced new threats.

**For `--stats`:**
Show the JSON statistics: total scans, unique plugins scanned, risk distribution, date range.

**For `--export`:**
Output the full JSON export. Ask the user if they want to save it to a file.

**For `--prune`:**
Report how many old entries were deleted.

### 3. Recommendations

- If any plugins show DEGRADED trends, recommend re-scanning those plugins with `/scan-plugin`
- If no history exists yet, suggest running `/scan-all` to establish a baseline
- Recommend periodic scans to build history for trend detection

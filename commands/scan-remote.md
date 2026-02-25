---
name: scan-remote
description: Scan a GitHub repository for security threats without cloning or installing it
argument-hint: <github-url-or-owner/repo> [--branch <branch>]
allowed-tools: [Read, Bash]
---

# Remote Scanner: Scan a GitHub Repo Without Installing

Scan a GitHub plugin repository for security threats without cloning it to your machine. Uses the GitHub API to fetch files into a temporary directory, runs the full scanner, then cleans up.

## Arguments

`$ARGUMENTS` — either:
- A GitHub URL: `https://github.com/user/plugin`
- An owner/repo slug: `user/plugin`
- Optionally followed by `--branch <branch>` to scan a specific branch

If no arguments provided, ask the user for the GitHub repository URL or owner/repo.

## Prerequisites

Requires the `gh` CLI to be installed and authenticated (`gh auth status`).

## Workflow

### 1. Run the Remote Scanner

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_remote.py $ARGUMENTS
```

If `python` is not found, try `python3` instead.

### 2. Parse the JSON Output

The scanner outputs the same JSON format as `/scan-plugin`, with additional fields:
- `scan_metadata.branch` — the branch that was scanned
- `scan_metadata.remote_scan` — true
- `scan_metadata.files_downloaded` — number of files fetched from GitHub

File paths in findings show `owner/repo/path` format.

### 3. Handle Errors

If the output contains an `error` field:
- "GitHub API error" — check if `gh` is installed and authenticated
- "Could not parse GitHub URL" — verify the URL format
- "Scan timed out" — the repo may be too large
- "Could not download any files" — the repo may be empty or private

### 4. Present the Security Report

Format the report the same as `/scan-plugin`:

**Repository:** owner/repo (branch)
**Overall Risk:** SAFE / CAUTION / DANGER

**Findings** grouped by severity with file paths, line numbers, descriptions, and recommendations.

### 5. Recommendations

- If SAFE: "This repo looks clean. You can install it with `/install-plugin`."
- If CAUTION: "Review the flagged findings before installing."
- If DANGER: "This repo has critical security issues. Do NOT install without thorough review."
- If known malicious signatures matched: "This repo matches known malicious tools. Do NOT install."

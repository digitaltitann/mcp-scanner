---
name: install-plugin
description: Safely install a plugin with pre-installation security scanning
args: path-or-url
---

# Safe Plugin Installation

Install a plugin with automatic security scanning before activation.

## Arguments

`$ARGUMENTS` — either:
- A **local directory path** containing a plugin (must have `.claude-plugin/` folder)
- A **Git repository URL** (HTTPS or SSH) to clone

## Workflow

### 1. Resolve the Source

Parse `$ARGUMENTS`:
- If it starts with `http://`, `https://`, or `git@` — it's a repository URL
- Otherwise — treat it as a local directory path

### 2. Prepare the Plugin

**For repository URLs:**
```bash
# Clone to a temporary location for scanning
git clone "<url>" "$TEMP/mcp-scanner-install-$(date +%s)"
```
The cloned directory is the scan target.

**For local paths:**
The provided path is the scan target directly.

### 3. Run Security Scan

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_plugin.py "<scan-target>"
```

Parse the JSON output and determine the risk level.

### 4. Also Run Dependency Audit (if available)

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/audit_deps.py "<scan-target>"
```

Include dependency findings in the assessment.

### 5. Present Results and Decide

**If SAFE (no findings or only INFO):**
- Display: "Security scan passed. No threats detected."
- Proceed to installation automatically.

**If CAUTION (LOW/MEDIUM findings):**
- Display all findings with details
- Ask: "This plugin has warnings. Do you want to install it anyway?"
- Only proceed if the user confirms

**If DANGER (CRITICAL/HIGH findings or known malicious):**
- Display all findings with emphasis on critical items
- If known malicious signatures matched: "This plugin matches a known malicious tool. DO NOT install."
- Ask: "This plugin has critical security issues. Are you absolutely sure you want to install it?"
- Strongly recommend NOT installing
- Only proceed if the user explicitly confirms

### 6. Install the Plugin

If proceeding:

**From a cloned repo:**
```bash
# Move from temp to plugins directory
mv "<temp-clone-path>" ~/.claude/plugins/<plugin-name>
```

**From a local path:**
```bash
# Copy to plugins directory
cp -r "<local-path>" ~/.claude/plugins/<plugin-name>
```

### 7. Post-Install

- Confirm installation location
- Update the gate scan baseline (so the SessionStart hook doesn't re-flag it):
  ```
  python ${CLAUDE_PLUGIN_ROOT}/hooks/gate_scan.py
  ```
- Remind the user to restart their Claude Code session to activate the plugin

## Notes

- Never install a plugin that matches known malicious signatures without extremely clear user consent
- If the clone or copy fails, report the error — do not proceed with a partial install
- The plugin name for the install directory is derived from the repo name or directory name

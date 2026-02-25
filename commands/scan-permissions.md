---
name: scan-permissions
description: Map what each installed plugin can access — hooks, network, files, env vars, subprocesses
argument-hint: <path-to-plugin> | --all
allowed-tools: [Read, Glob, Grep, Bash]
---

# Permission Mapper: Plugin Access Analysis

Analyze what a plugin (or all plugins) can access: hooks, skills, commands, network calls, file system access, environment variables, and subprocess execution.

## Arguments

`$ARGUMENTS` — either:
- A path to a specific plugin directory
- `--all` to scan every installed plugin

If no arguments provided, ask the user whether to scan a specific plugin or all of them.

## Workflow

### 1. Run the Permission Scanner

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_permissions.py $ARGUMENTS
```

If `python` is not found, try `python3` instead.

### 2. Parse the JSON Output

**For a single plugin**, the output includes:
- `permissions` — list of capability flags: HOOKS, WILDCARD_HOOKS, SKILLS, COMMANDS, NETWORK, FILESYSTEM, ENVIRONMENT, SUBPROCESS
- `risk_factors` — specific concerns (e.g., "Network access + environment access = potential exfiltration")
- `hooks` — events intercepted, tools matched, hook scripts
- `skills` — skill names, tools referenced, bash commands mentioned
- `commands` — command names, bash code blocks used
- `code_analysis` — network, file, env, and subprocess access patterns with file locations

**For `--all`**, the output adds:
- `permission_matrix` — a map of plugin name → permission flags for quick comparison

### 3. Present the Permission Report

**Permission Summary:**
Display the permission flags as a clear list with icons:
- HOOKS — can intercept tool calls
- WILDCARD_HOOKS — intercepts ALL tools (high risk)
- NETWORK — makes network requests
- ENVIRONMENT — reads environment variables
- SUBPROCESS — executes system commands
- FILESYSTEM — reads/writes files

**Risk Factors:**
List any risk factor combinations detected (these indicate elevated concern).

**Detailed Access:**
For each access type, show which files contain the access patterns.

**For `--all` — Permission Matrix:**
Display a comparison table:

| Plugin | Hooks | Network | Env | Files | Subprocess |
|--------|-------|---------|-----|-------|------------|

### 4. Recommendations

- WILDCARD_HOOKS is the highest risk — a plugin intercepting all tools can see and modify everything
- NETWORK + ENVIRONMENT together = potential data exfiltration path
- SUBPROCESS in a hooked plugin = can execute arbitrary commands triggered by tool calls
- Recommend reviewing any plugin with 3+ permission types

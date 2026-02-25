---
name: scan-mcp
description: Scan all MCP server configurations from Claude Code settings for security issues
---

# Scan MCP Server Configurations

Analyze all MCP server definitions from Claude Code settings files for security risks.

## Workflow

### 1. Run the MCP Settings Scanner

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/scan_mcp_settings.py
```

This scans:
- `~/.claude/settings.json` (global settings)
- `~/.claude/projects/*/settings.json` (project-specific settings)
- `.mcp.json` files in plugin directories

### 2. Parse the JSON Output

The scanner outputs a JSON report with:
- List of all MCP servers found (name, type, URL/command, source file)
- Security findings for each server
- Overall risk assessment

### 3. Present the Results

**Server Inventory:**
List all discovered MCP servers in a table:

| Server Name | Type | Endpoint | Source | Risk |
|-------------|------|----------|--------|------|

**Findings by Severity:**
For each finding, show:
- Severity and category
- Server name and source file
- What was found and why it's a risk
- Recommendation

### 4. Check What the Servers Can Access

For each MCP server, note:
- What environment variables it has access to (via `env` config)
- What command it runs (for stdio-type servers)
- What URL it connects to (for sse/streamable-http servers)
- Whether it uses HTTPS or plain HTTP

### 5. Recommendations

Common issues to flag:
- HTTP instead of HTTPS for remote servers
- Credentials hardcoded in URLs or headers (should use env var references)
- Servers running arbitrary commands with shell=true
- Servers with access to sensitive environment variables
- Servers connecting to known exfiltration/tunneling services
- Servers with overly broad tool permissions

## Notes

- MCP servers are a significant attack surface — they can intercept tool calls and access data
- Even "trusted" MCP servers should use HTTPS and env var references for credentials
- A server running on localhost is less risky than a remote one, but still review its command

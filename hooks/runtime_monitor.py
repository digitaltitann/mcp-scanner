#!/usr/bin/env python3
"""
Runtime Behavior Monitor — PreToolUse hook for real-time threat detection.

Intercepts tool calls (Bash, Write, Edit) and checks for suspicious patterns
before they execute. Blocks dangerous operations and warns about risky ones.

Hook events: PreToolUse (Bash, Write, Edit)
Input: JSON on stdin with tool_name, tool_input
Output: JSON on stderr with decision (block/allow) + optional systemMessage
Exit: 0 = allow, 2 = block
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Log file for monitoring events
LOG_DIR = os.path.expanduser("~/.claude/mcp-scanner-reports")
LOG_FILE = os.path.join(LOG_DIR, "runtime-monitor.log")

# ============================================================================
# BASH COMMAND PATTERNS
# ============================================================================

# Commands that should be BLOCKED (exit 2)
BASH_BLOCK_PATTERNS = [
    {
        "id": "RT_BASH_001",
        "pattern": re.compile(r'\b(?:nc|netcat|ncat)\b\s+.*-[elp]', re.IGNORECASE),
        "description": "Reverse shell via netcat",
        "reason": "Blocked: netcat with shell/listen flags is a reverse shell pattern"
    },
    {
        "id": "RT_BASH_002",
        "pattern": re.compile(r'bash\s+-i\s+>&\s*/dev/tcp/', re.IGNORECASE),
        "description": "Bash reverse shell via /dev/tcp",
        "reason": "Blocked: bash reverse shell to remote host"
    },
    {
        "id": "RT_BASH_003",
        "pattern": re.compile(r'python[23]?\s+-c\s+["\']import\s+(?:socket|os|subprocess)', re.IGNORECASE),
        "description": "Python one-liner reverse shell",
        "reason": "Blocked: Python one-liner with socket/os imports — likely reverse shell"
    },
    {
        "id": "RT_BASH_004",
        "pattern": re.compile(r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|python|perl|ruby)', re.IGNORECASE),
        "description": "Download and execute pattern (curl | bash)",
        "reason": "Blocked: downloading and piping directly to a shell interpreter"
    },
    {
        "id": "RT_BASH_005",
        "pattern": re.compile(r'(?:rm\s+-rf?\s+[~/]\s|rm\s+-rf?\s+/(?:home|Users))', re.IGNORECASE),
        "description": "Destructive recursive deletion of home directory",
        "reason": "Blocked: recursive deletion targeting home directory"
    },
    {
        "id": "RT_BASH_006",
        "pattern": re.compile(r'mkfifo\s+.*\|\s*(?:bash|sh|nc)', re.IGNORECASE),
        "description": "Named pipe reverse shell",
        "reason": "Blocked: named pipe used with shell — reverse shell pattern"
    },
    {
        "id": "RT_BASH_007",
        "pattern": re.compile(r'(?:socat|telnet)\s+.*(?:exec|pty|tcp)', re.IGNORECASE),
        "description": "Socat/telnet reverse shell",
        "reason": "Blocked: socat/telnet with exec or pty — reverse shell pattern"
    },
]

# Commands that should generate WARNINGS (exit 0 + systemMessage)
BASH_WARN_PATTERNS = [
    {
        "id": "RT_BASH_W01",
        "pattern": re.compile(r'(?:curl|wget|fetch)\s+.*(?:webhook\.site|requestbin|hookbin|pipedream|pastebin)', re.IGNORECASE),
        "description": "Network request to known exfiltration service",
        "warning": "Warning: command contacts a known data exfiltration service"
    },
    {
        "id": "RT_BASH_W02",
        "pattern": re.compile(r'(?:curl|wget)\s+.*-[dX]\s.*(?:\$|env|secret|password|token|key)', re.IGNORECASE),
        "description": "Sending sensitive data via curl/wget",
        "warning": "Warning: command appears to send sensitive data (secrets/tokens) externally"
    },
    {
        "id": "RT_BASH_W03",
        "pattern": re.compile(r'(?:cat|type)\s+.*\.(?:env|ssh|aws|kube|docker)', re.IGNORECASE),
        "description": "Reading sensitive config files",
        "warning": "Warning: command reads sensitive configuration files"
    },
    {
        "id": "RT_BASH_W04",
        "pattern": re.compile(r'(?:chmod|icacls)\s+.*(?:\+x|777|755|\/grant)', re.IGNORECASE),
        "description": "Changing file permissions to executable",
        "warning": "Warning: command modifies file permissions"
    },
    {
        "id": "RT_BASH_W05",
        "pattern": re.compile(r'(?:schtasks|crontab|at\s+\d)', re.IGNORECASE),
        "description": "Creating scheduled tasks",
        "warning": "Warning: command creates or modifies scheduled tasks"
    },
    {
        "id": "RT_BASH_W06",
        "pattern": re.compile(r'(?:base64|openssl)\s+.*(?:-d|decode|enc)', re.IGNORECASE),
        "description": "Encoding/decoding data (possible obfuscation)",
        "warning": "Warning: command performs encoding/decoding — may be obfuscating data"
    },
    {
        "id": "RT_BASH_W07",
        "pattern": re.compile(r'(?:nslookup|dig)\s+.*(?:\$|\{|%)', re.IGNORECASE),
        "description": "DNS query with variable interpolation",
        "warning": "Warning: DNS query with dynamic data — possible DNS exfiltration"
    },
    {
        "id": "RT_BASH_W08",
        "pattern": re.compile(r'powershell\s+.*(?:-enc|-e\s+[A-Za-z0-9+/=]{20,})', re.IGNORECASE),
        "description": "PowerShell with encoded command",
        "warning": "Warning: PowerShell encoded command — may hide malicious payload"
    },
]

# ============================================================================
# FILE WRITE PATTERNS (for Write and Edit tools)
# ============================================================================

SENSITIVE_WRITE_PATHS = [
    {
        "id": "RT_WRITE_001",
        "pattern": re.compile(r'[/\\]\.(?:bashrc|zshrc|profile|bash_profile|zprofile)$', re.IGNORECASE),
        "description": "Writing to shell configuration file",
        "reason": "Blocked: modifying shell config files can install persistent backdoors"
    },
    {
        "id": "RT_WRITE_002",
        "pattern": re.compile(r'[/\\]\.ssh[/\\]', re.IGNORECASE),
        "description": "Writing to SSH directory",
        "reason": "Blocked: modifying SSH keys or config can enable unauthorized access"
    },
    {
        "id": "RT_WRITE_003",
        "pattern": re.compile(r'[/\\]\.(?:aws|kube|docker)[/\\]', re.IGNORECASE),
        "description": "Writing to cloud credentials directory",
        "reason": "Blocked: modifying cloud credential configs is a security risk"
    },
    {
        "id": "RT_WRITE_004",
        "pattern": re.compile(r'[/\\](?:hosts|sudoers|passwd|shadow|crontab)$', re.IGNORECASE),
        "description": "Writing to system file",
        "reason": "Blocked: modifying system files can compromise the operating system"
    },
    {
        "id": "RT_WRITE_005",
        "pattern": re.compile(r'[/\\]\.(?:env|env\.local|env\.production)$', re.IGNORECASE),
        "description": "Writing to environment file",
        "reason": "Blocked: modifying .env files can expose or alter secrets"
    },
]

SENSITIVE_WRITE_WARN_PATHS = [
    {
        "id": "RT_WRITE_W01",
        "pattern": re.compile(r'[/\\]\.claude[/\\]', re.IGNORECASE),
        "description": "Writing to Claude config directory",
        "warning": "Warning: a tool is modifying files in the Claude configuration directory"
    },
    {
        "id": "RT_WRITE_W02",
        "pattern": re.compile(r'[/\\]\.git[/\\](?:config|hooks)', re.IGNORECASE),
        "description": "Writing to Git hooks or config",
        "warning": "Warning: modifying Git hooks or config — could install persistent hooks"
    },
]


def log_event(event_type, tool_name, detail, decision):
    """Log a monitoring event to the log file."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"[{timestamp}] {event_type} | {tool_name} | {decision} | {detail}\n"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except IOError:
        pass


def check_bash_command(command):
    """Check a Bash command for dangerous patterns. Returns (decision, message)."""
    if not isinstance(command, str):
        return "allow", None

    # Check block patterns
    for pattern_def in BASH_BLOCK_PATTERNS:
        if pattern_def["pattern"].search(command):
            log_event("BLOCK", "Bash", f"{pattern_def['id']}: {command[:200]}", "blocked")
            return "block", pattern_def["reason"]

    # Check warn patterns
    warnings = []
    for pattern_def in BASH_WARN_PATTERNS:
        if pattern_def["pattern"].search(command):
            warnings.append(pattern_def["warning"])
            log_event("WARN", "Bash", f"{pattern_def['id']}: {command[:200]}", "warned")

    if warnings:
        return "allow", "[MCP Monitor] " + "; ".join(warnings)

    return "allow", None


def check_file_write(file_path):
    """Check a file write/edit target for sensitive paths. Returns (decision, message)."""
    if not isinstance(file_path, str):
        return "allow", None

    # Check block patterns
    for pattern_def in SENSITIVE_WRITE_PATHS:
        if pattern_def["pattern"].search(file_path):
            log_event("BLOCK", "Write/Edit", f"{pattern_def['id']}: {file_path}", "blocked")
            return "block", pattern_def["reason"]

    # Check warn patterns
    for pattern_def in SENSITIVE_WRITE_WARN_PATHS:
        if pattern_def["pattern"].search(file_path):
            log_event("WARN", "Write/Edit", f"{pattern_def['id']}: {file_path}", "warned")
            return "allow", f"[MCP Monitor] {pattern_def['warning']}"

    return "allow", None


def main():
    # Read hook input from stdin
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.exit(0)
        hook_data = json.loads(raw_input)
    except (json.JSONDecodeError, IOError):
        sys.exit(0)  # Allow on parse error — don't block legitimate operations

    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})

    decision = "allow"
    message = None

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        decision, message = check_bash_command(command)

    elif tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        decision, message = check_file_write(file_path)

    # Output decision
    if decision == "block":
        output = {"decision": "block", "reason": message or "Blocked by MCP Scanner runtime monitor"}
        print(json.dumps(output), file=sys.stderr)
        sys.exit(2)

    elif message:
        # Allow with warning
        output = {"systemMessage": message}
        print(json.dumps(output), file=sys.stderr)
        sys.exit(0)

    else:
        # Allow silently
        sys.exit(0)


if __name__ == "__main__":
    main()

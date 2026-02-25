#!/usr/bin/env python3
"""
MCP Settings Scanner — scans Claude Code settings for risky MCP server configurations.

Reads MCP server definitions from:
  - ~/.claude/settings.json (global)
  - ~/.claude/projects/*/settings.json (per-project)
  - ~/.claude/plugins/*/.mcp.json (plugin-bundled)

Checks for: HTTP instead of HTTPS, hardcoded credentials, suspicious commands,
access to sensitive env vars, connections to known exfiltration services, etc.

Usage: python scan_mcp_settings.py [--json | --summary]
Output: JSON report to stdout (default) or summary text
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CLAUDE_DIR = os.path.expanduser("~/.claude")
SETTINGS_FILE = os.path.join(CLAUDE_DIR, "settings.json")
PROJECTS_DIR = os.path.join(CLAUDE_DIR, "projects")
PLUGINS_DIR = os.path.join(CLAUDE_DIR, "plugins")

# Known exfiltration/tunneling services
SUSPICIOUS_DOMAINS = {
    "pastebin.com", "hastebin.com", "webhook.site", "requestbin.com",
    "hookbin.com", "pipedream.net", "file.io", "transfer.sh", "0x0.st",
    "ngrok.io", "burpcollaborator.net", "interact.sh", "oastify.com",
    "requestcatcher.com", "canarytokens.com",
}

# Sensitive env var patterns
SENSITIVE_ENV_PATTERNS = re.compile(
    r'(?:PASSWORD|SECRET|PRIVATE.?KEY|CREDENTIAL|AUTH.?TOKEN|SESSION.?KEY|'
    r'SSH.?KEY|MASTER.?KEY|SIGNING.?KEY|ENCRYPTION.?KEY|DATABASE.?URL|'
    r'DB.?PASSWORD|SMTP.?PASSWORD|EVIL|EXFIL|C2|BEACON|BACKDOOR)',
    re.IGNORECASE
)


def find_settings_files():
    """Find all Claude settings files that may contain MCP server configs."""
    files = []

    # Global settings
    if os.path.exists(SETTINGS_FILE):
        files.append(("global", SETTINGS_FILE))

    # Project-specific settings
    projects_path = Path(PROJECTS_DIR)
    if projects_path.exists():
        for settings_file in projects_path.rglob("settings.json"):
            project_name = settings_file.parent.name
            files.append((f"project:{project_name}", str(settings_file)))

    # Plugin-bundled MCP configs
    plugins_path = Path(PLUGINS_DIR)
    if plugins_path.exists():
        for mcp_file in plugins_path.rglob(".mcp.json"):
            rel_path = mcp_file.relative_to(plugins_path)
            plugin_name = str(rel_path).split(os.sep)[0]
            files.append((f"plugin:{plugin_name}", str(mcp_file)))

    return files


def extract_mcp_servers(file_path):
    """Extract MCP server definitions from a settings/config file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

    # Settings files have mcpServers at top level
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        return data["mcpServers"]

    # .mcp.json files may have servers directly
    if any(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values() if isinstance(v, dict)):
        return data

    return {}


def check_url(url, server_name):
    """Check a server URL for security issues."""
    findings = []

    if not isinstance(url, str) or not url:
        return findings

    # HTTP instead of HTTPS
    if url.startswith("http://"):
        is_local = any(host in url for host in ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"])
        if not is_local:
            findings.append({
                "severity": "HIGH",
                "category": "network-abuse",
                "description": f"Server '{server_name}' uses HTTP instead of HTTPS",
                "detail": f"URL: {url[:100]}",
                "recommendation": "Use HTTPS to encrypt data in transit"
            })

    # Embedded credentials
    if re.search(r'://[^/]*:[^@/]*@', url):
        findings.append({
            "severity": "CRITICAL",
            "category": "credential-exposure",
            "description": f"Server '{server_name}' has credentials embedded in URL",
            "detail": "Credentials in URLs appear in logs and process lists",
            "recommendation": "Move credentials to environment variables"
        })

    # Known suspicious domains
    for domain in SUSPICIOUS_DOMAINS:
        if domain in url.lower():
            findings.append({
                "severity": "CRITICAL",
                "category": "data-exfiltration",
                "description": f"Server '{server_name}' connects to suspicious service: {domain}",
                "detail": f"URL: {url[:100]}",
                "recommendation": f"{domain} is commonly used for data exfiltration"
            })

    # Unencrypted WebSocket
    if url.startswith("ws://") and "localhost" not in url and "127.0.0.1" not in url:
        findings.append({
            "severity": "HIGH",
            "category": "network-abuse",
            "description": f"Server '{server_name}' uses unencrypted WebSocket (ws:// instead of wss://)",
            "detail": f"URL: {url[:100]}",
            "recommendation": "Use WSS for encrypted WebSocket connections"
        })

    return findings


def check_command(config, server_name):
    """Check a stdio-type server's command for security issues."""
    findings = []

    command = config.get("command", "")
    args = config.get("args", [])

    if not isinstance(command, str):
        return findings

    full_cmd = command + " " + " ".join(str(a) for a in args) if args else command

    # Shell injection risk
    if any(shell_char in full_cmd for shell_char in ["|", "&&", "||", ";", "`", "$("]):
        findings.append({
            "severity": "HIGH",
            "category": "code-execution",
            "description": f"Server '{server_name}' command contains shell metacharacters",
            "detail": f"Command: {full_cmd[:150]}",
            "recommendation": "Avoid shell metacharacters in MCP server commands"
        })

    # Running from temp or download directories
    if re.search(r'(?:/tmp/|\\temp\\|\\downloads\\|/var/tmp/)', full_cmd, re.IGNORECASE):
        findings.append({
            "severity": "MEDIUM",
            "category": "code-execution",
            "description": f"Server '{server_name}' runs from a temporary/downloads directory",
            "detail": f"Command: {full_cmd[:150]}",
            "recommendation": "MCP servers should run from stable, known directories"
        })

    # Running with explicit shell
    if re.search(r'(?:cmd\.exe|powershell|bash\s+-c|sh\s+-c)', full_cmd, re.IGNORECASE):
        findings.append({
            "severity": "MEDIUM",
            "category": "code-execution",
            "description": f"Server '{server_name}' explicitly invokes a shell",
            "detail": f"Command: {full_cmd[:150]}",
            "recommendation": "Direct execution is safer than shell invocation"
        })

    return findings


def check_env(config, server_name):
    """Check environment variable configuration for sensitive data."""
    findings = []

    env = config.get("env", {})
    if not isinstance(env, dict):
        return findings

    for var_name, var_value in env.items():
        # Sensitive env var names with hardcoded values (not env var references)
        if isinstance(var_value, str) and not var_value.startswith("${"):
            if SENSITIVE_ENV_PATTERNS.search(var_name):
                findings.append({
                    "severity": "HIGH",
                    "category": "credential-exposure",
                    "description": f"Server '{server_name}' has hardcoded sensitive env var: {var_name}",
                    "detail": "Value is hardcoded instead of referenced from system environment",
                    "recommendation": f"Use ${{env:{var_name}}} reference instead of hardcoding the value"
                })

        # Suspicious env var names
        if re.search(r'(?:EVIL|EXFIL|C2|BEACON|BACKDOOR|MALWARE|PAYLOAD)', var_name, re.IGNORECASE):
            findings.append({
                "severity": "CRITICAL",
                "category": "credential-theft",
                "description": f"Server '{server_name}' has suspiciously named env var: {var_name}",
                "detail": "Environment variable name suggests malicious purpose",
                "recommendation": "Investigate this MCP server immediately"
            })

    return findings


def check_headers(config, server_name):
    """Check HTTP headers for hardcoded credentials."""
    findings = []

    headers = config.get("headers", {})
    if not isinstance(headers, dict):
        return findings

    for header_name, header_value in headers.items():
        if not isinstance(header_value, str):
            continue

        # Hardcoded auth tokens (not env var references)
        if not header_value.startswith("${"):
            header_lower = header_name.lower()
            value_lower = header_value.lower()
            if any(auth_word in header_lower or auth_word in value_lower
                   for auth_word in ["authorization", "bearer", "token", "api-key", "x-api-key"]):
                findings.append({
                    "severity": "HIGH",
                    "category": "credential-exposure",
                    "description": f"Server '{server_name}' has hardcoded auth in header '{header_name}'",
                    "detail": "Authentication should use environment variable references",
                    "recommendation": f"Use ${{env:YOUR_TOKEN_VAR}} instead of hardcoding"
                })

    return findings


def scan_all_settings():
    """Scan all settings files and produce a consolidated report."""
    settings_files = find_settings_files()
    all_servers = []
    all_findings = []

    for source_label, file_path in settings_files:
        servers = extract_mcp_servers(file_path)

        for server_name, config in servers.items():
            if not isinstance(config, dict):
                continue

            server_type = config.get("type", "unknown")
            url = config.get("url", "")
            command = config.get("command", "")

            server_info = {
                "name": server_name,
                "type": server_type,
                "endpoint": url or command or "(unknown)",
                "source": source_label,
                "source_file": file_path,
            }
            all_servers.append(server_info)

            # Run all checks
            server_findings = []
            server_findings.extend(check_url(url, server_name))
            server_findings.extend(check_command(config, server_name))
            server_findings.extend(check_env(config, server_name))
            server_findings.extend(check_headers(config, server_name))

            for finding in server_findings:
                finding["server"] = server_name
                finding["source"] = source_label
                finding["source_file"] = file_path

            all_findings.extend(server_findings)

    # Determine overall risk
    severity_counts = {}
    for f in all_findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts.get("CRITICAL", 0) > 0:
        overall_risk = "DANGER"
    elif severity_counts.get("HIGH", 0) > 0:
        overall_risk = "CAUTION"
    elif severity_counts.get("MEDIUM", 0) > 0:
        overall_risk = "CAUTION"
    else:
        overall_risk = "SAFE"

    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    report = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": "mcp-settings-scanner",
            "settings_files_checked": len(settings_files),
            "servers_found": len(all_servers),
        },
        "summary": {
            "overall_risk": overall_risk,
            "total_findings": len(all_findings),
            "by_severity": severity_counts,
        },
        "servers": all_servers,
        "findings": all_findings,
    }

    return report


def print_summary(report):
    """Print a human-readable summary."""
    meta = report["scan_metadata"]
    summary = report["summary"]
    servers = report["servers"]
    findings = report["findings"]

    print(f"MCP Server Security Scan — {meta['timestamp'][:19]} UTC")
    print(f"{'=' * 60}")
    print(f"Settings files checked: {meta['settings_files_checked']}")
    print(f"MCP servers found:     {meta['servers_found']}")
    print(f"Overall risk:          {summary['overall_risk']}")
    print(f"Total findings:        {summary['total_findings']}")
    print()

    if servers:
        print("Servers:")
        for s in servers:
            endpoint = s["endpoint"][:60] if len(s["endpoint"]) > 60 else s["endpoint"]
            print(f"  [{s['source']}] {s['name']} ({s['type']}) — {endpoint}")
        print()

    if findings:
        print("Findings:")
        for f in findings:
            print(f"  [{f['severity']}] {f['description']}")
            print(f"    {f['detail']}")
            print(f"    Fix: {f['recommendation']}")
            print()
    else:
        print("No security issues found.")


def main():
    report = scan_all_settings()

    if "--summary" in sys.argv:
        print_summary(report)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

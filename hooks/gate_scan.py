#!/usr/bin/env python3
"""
Gate Scan Hook — SessionStart hook for mcp-scanner plugin.

Runs at the start of every Claude Code session. Computes checksums of all
installed plugins and compares against a stored baseline. If any plugin is
new or has changed files, runs the security scanner on it and warns the user.

State file: ~/.claude/mcp-scanner-state.json
"""

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


STATE_FILE = os.path.expanduser("~/.claude/mcp-scanner-state.json")
PLUGINS_DIR = os.path.expanduser("~/.claude/plugins")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
                   ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp",
                   ".mp3", ".mp4", ".wav", ".zip", ".tar", ".gz", ".7z",
                   ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf"}


def get_plugin_dirs():
    """Find all plugin directories (those containing .claude-plugin/)."""
    plugin_dirs = []
    plugins_path = Path(PLUGINS_DIR)
    if not plugins_path.exists():
        return plugin_dirs

    # Walk through all directories looking for .claude-plugin/ markers
    for root, dirs, files in os.walk(str(plugins_path)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        plugin_marker = Path(root) / ".claude-plugin"
        if plugin_marker.is_dir():
            plugin_dirs.append(Path(root))
            dirs.clear()  # Don't descend into plugin subdirectories

    return plugin_dirs


def compute_plugin_checksum(plugin_dir):
    """Compute a combined hash of all scannable files in a plugin directory."""
    hasher = hashlib.sha256()
    file_count = 0

    for root, dirs, files in os.walk(str(plugin_dir)):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)

        for filename in sorted(files):
            file_path = Path(root) / filename
            ext = file_path.suffix.lower()
            if ext in SKIP_EXTENSIONS:
                continue
            try:
                content = file_path.read_bytes()
                # Hash the relative path + content so renames are detected
                rel_path = str(file_path.relative_to(plugin_dir))
                hasher.update(rel_path.encode("utf-8"))
                hasher.update(content)
                file_count += 1
            except (OSError, IOError):
                continue

    return hasher.hexdigest(), file_count


def load_state():
    """Load the saved plugin checksums state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"checksums": {}, "last_scan": None}


def save_state(state):
    """Save the plugin checksums state."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except IOError:
        pass


def run_scanner(plugin_dir):
    """Run the scanner on a plugin and return the risk level and finding count."""
    scanner_path = os.path.join(os.environ.get("CLAUDE_PLUGIN_ROOT", ""), "scripts", "scan_plugin.py")
    if not os.path.exists(scanner_path):
        # Fallback: look relative to this script
        scanner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "scan_plugin.py")

    try:
        result = subprocess.run(
            [sys.executable, scanner_path, str(plugin_dir)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            report = json.loads(result.stdout)
            return report.get("summary", {})
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def main():
    # Read hook input from stdin (SessionStart provides minimal data)
    try:
        raw_input = sys.stdin.read()
    except Exception:
        pass

    state = load_state()
    saved_checksums = state.get("checksums", {})

    # Find all plugins
    plugin_dirs = get_plugin_dirs()
    current_checksums = {}
    new_plugins = []
    changed_plugins = []

    for plugin_dir in plugin_dirs:
        plugin_name = str(plugin_dir)
        checksum, file_count = compute_plugin_checksum(plugin_dir)
        current_checksums[plugin_name] = {"checksum": checksum, "files": file_count}

        if plugin_name not in saved_checksums:
            new_plugins.append(plugin_dir)
        elif saved_checksums[plugin_name].get("checksum") != checksum:
            changed_plugins.append(plugin_dir)

    # If there are new or changed plugins, scan them
    warnings = []
    plugins_to_scan = new_plugins + changed_plugins

    for plugin_dir in plugins_to_scan:
        plugin_name = plugin_dir.name
        status = "NEW" if plugin_dir in new_plugins else "CHANGED"
        summary = run_scanner(plugin_dir)

        if summary and summary.get("overall_risk") in ("DANGER", "CAUTION"):
            risk = summary["overall_risk"]
            total = summary.get("total_findings", 0)
            crit = summary.get("by_severity", {}).get("CRITICAL", 0)
            high = summary.get("by_severity", {}).get("HIGH", 0)
            known = summary.get("by_category", {}).get("known-malicious", 0)

            warning_parts = [f"[MCP Scanner] {status} plugin '{plugin_name}': {risk}"]
            warning_parts.append(f"  Findings: {total} total (CRITICAL:{crit} HIGH:{high})")
            if known > 0:
                warning_parts.append(f"  WARNING: {known} known malicious signature(s) matched!")
            warning_parts.append(f"  Run /scan-plugin {plugin_dir} for full report")
            warnings.append("\n".join(warning_parts))

    # Save updated state
    state["checksums"] = current_checksums
    state["last_scan"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    # Output warnings as systemMessage if any threats found
    if warnings:
        message = "\n\n".join(warnings)
        output = {"systemMessage": message}
        print(json.dumps(output), file=sys.stderr)
        # Exit 0 — don't block session, just warn
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

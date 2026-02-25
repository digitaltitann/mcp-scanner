#!/usr/bin/env python3
"""
Daily Integrity Scan — scans all installed plugins and generates a report.

Run via Windows Task Scheduler or cron. Scans every plugin in ~/.claude/plugins/
and writes a timestamped report to ~/.claude/mcp-scanner-reports/.

Usage:
    python daily_scan.py              # Scan and generate report
    python daily_scan.py --install    # Install as Windows scheduled task (daily at 8 AM)
    python daily_scan.py --uninstall  # Remove the scheduled task

Reports are stored at: ~/.claude/mcp-scanner-reports/scan-YYYY-MM-DD.json
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PLUGINS_DIR = os.path.expanduser("~/.claude/plugins")
REPORTS_DIR = os.path.expanduser("~/.claude/mcp-scanner-reports")
SCANNER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_plugin.py")
TASK_NAME = "MCPScannerDailyScan"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def find_plugins():
    """Find all plugin directories."""
    plugin_dirs = []
    plugins_path = Path(PLUGINS_DIR)
    if not plugins_path.exists():
        return plugin_dirs

    for root, dirs, files in os.walk(str(plugins_path)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        plugin_marker = Path(root) / ".claude-plugin"
        if plugin_marker.is_dir():
            plugin_dirs.append(Path(root))
            dirs.clear()

    return plugin_dirs


def scan_plugin(plugin_dir):
    """Run the scanner on a single plugin and return the report."""
    try:
        result = subprocess.run(
            [sys.executable, SCANNER_SCRIPT, str(plugin_dir)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": f"Scanner failed for {plugin_dir}", "stderr": result.stderr[:500]}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return {"error": f"Scanner error for {plugin_dir}: {str(e)}"}


def run_daily_scan():
    """Scan all plugins and generate a consolidated report."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    plugins = find_plugins()
    timestamp = datetime.now(timezone.utc)
    report_file = os.path.join(REPORTS_DIR, f"scan-{timestamp.strftime('%Y-%m-%d')}.json")

    results = []
    danger_count = 0
    caution_count = 0
    safe_count = 0

    for plugin_dir in plugins:
        report = scan_plugin(plugin_dir)
        risk = report.get("summary", {}).get("overall_risk", "UNKNOWN")
        plugin_name = plugin_dir.name

        results.append({
            "plugin": plugin_name,
            "path": str(plugin_dir),
            "risk": risk,
            "total_findings": report.get("summary", {}).get("total_findings", 0),
            "by_severity": report.get("summary", {}).get("by_severity", {}),
            "by_category": report.get("summary", {}).get("by_category", {}),
            "known_malicious": report.get("summary", {}).get("by_category", {}).get("known-malicious", 0),
            "findings": report.get("findings", [])
        })

        if risk == "DANGER":
            danger_count += 1
        elif risk == "CAUTION":
            caution_count += 1
        else:
            safe_count += 1

    consolidated = {
        "scan_metadata": {
            "timestamp": timestamp.isoformat(),
            "scanner_version": "1.1.0",
            "plugins_scanned": len(plugins),
            "report_file": report_file
        },
        "summary": {
            "danger": danger_count,
            "caution": caution_count,
            "safe": safe_count,
            "overall": "DANGER" if danger_count > 0 else ("CAUTION" if caution_count > 0 else "SAFE")
        },
        "results": results
    }

    with open(report_file, "w") as f:
        json.dump(consolidated, f, indent=2)

    # Print summary to stdout
    print(f"MCP Scanner Daily Report — {timestamp.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"Plugins scanned: {len(plugins)}")
    print(f"Results: {safe_count} SAFE | {caution_count} CAUTION | {danger_count} DANGER")

    if danger_count > 0:
        print("\nDANGER plugins:")
        for r in results:
            if r["risk"] == "DANGER":
                known = r.get("known_malicious", 0)
                known_str = f" [{known} KNOWN MALICIOUS]" if known > 0 else ""
                print(f"  - {r['plugin']}: {r['total_findings']} findings{known_str}")
                print(f"    Path: {r['path']}")

    print(f"\nFull report: {report_file}")

    # Clean up reports older than 30 days
    cleanup_old_reports()

    return consolidated


def cleanup_old_reports():
    """Remove report files older than 30 days."""
    try:
        cutoff = datetime.now().timestamp() - (30 * 24 * 60 * 60)
        for f in Path(REPORTS_DIR).glob("scan-*.json"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
    except (OSError, IOError):
        pass


def install_scheduled_task():
    """Install a Windows Task Scheduler task to run daily at 8 AM."""
    python_path = sys.executable
    script_path = os.path.abspath(__file__)

    cmd = (
        f'schtasks /create /tn "{TASK_NAME}" /tr '
        f'"\"{python_path}\" \"{script_path}\"" '
        f'/sc daily /st 08:00 /f'
    )

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Scheduled task '{TASK_NAME}' installed successfully.")
            print(f"  Runs daily at 08:00")
            print(f"  Python: {python_path}")
            print(f"  Script: {script_path}")
            print(f"  Reports: {REPORTS_DIR}")
        else:
            print(f"Failed to install scheduled task: {result.stderr}")
            print("Try running as Administrator.")
    except OSError as e:
        print(f"Error: {e}")


def uninstall_scheduled_task():
    """Remove the Windows Task Scheduler task."""
    cmd = f'schtasks /delete /tn "{TASK_NAME}" /f'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Scheduled task '{TASK_NAME}' removed.")
        else:
            print(f"Failed to remove task: {result.stderr}")
    except OSError as e:
        print(f"Error: {e}")


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            install_scheduled_task()
        elif sys.argv[1] == "--uninstall":
            uninstall_scheduled_task()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: daily_scan.py [--install | --uninstall]")
    else:
        run_daily_scan()


if __name__ == "__main__":
    main()

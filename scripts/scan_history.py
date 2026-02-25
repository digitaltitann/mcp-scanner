#!/usr/bin/env python3
"""
Scan History — track scan results over time in a local SQLite database.

Stores scan results with timestamps and detects when a previously SAFE
plugin becomes CAUTION/DANGER after an update.

Usage:
    python scan_history.py --save <json-report>    Save a scan result
    python scan_history.py --show [plugin-name]    Show history
    python scan_history.py --show-all              Show all plugins
    python scan_history.py --trends                Show risk trend changes
    python scan_history.py --export                Export all history as JSON
    python scan_history.py --prune <days>          Delete entries older than N days
Output: Formatted text or JSON to stdout
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB_DIR = os.path.expanduser("~/.claude/mcp-scanner-reports")
DB_FILE = os.path.join(DB_DIR, "scan_history.db")


def init_db():
    """Initialize the database and create tables if needed."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            plugin_name TEXT NOT NULL,
            plugin_path TEXT NOT NULL,
            overall_risk TEXT NOT NULL,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            signatures_total INTEGER DEFAULT 0,
            allowlist_suppressed INTEGER DEFAULT 0,
            categories TEXT DEFAULT '{}',
            scanner_version TEXT DEFAULT '',
            raw_summary TEXT DEFAULT '{}'
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_plugin_name ON scan_history(plugin_name)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp)
    """)
    conn.commit()
    return conn


def save_scan(report, conn=None):
    """Save a scan report to the database."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    meta = report.get("scan_metadata", {})
    summary = report.get("summary", {})
    by_severity = summary.get("by_severity", {})

    target_path = meta.get("target", "")
    plugin_name = Path(target_path).name if target_path else "unknown"

    conn.execute("""
        INSERT INTO scan_history (
            timestamp, plugin_name, plugin_path, overall_risk, total_findings,
            critical_count, high_count, medium_count, low_count, info_count,
            files_scanned, signatures_total, allowlist_suppressed,
            categories, scanner_version, raw_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
        plugin_name,
        target_path,
        summary.get("overall_risk", "UNKNOWN"),
        summary.get("total_findings", 0),
        by_severity.get("CRITICAL", 0),
        by_severity.get("HIGH", 0),
        by_severity.get("MEDIUM", 0),
        by_severity.get("LOW", 0),
        by_severity.get("INFO", 0),
        meta.get("files_scanned", 0),
        meta.get("signatures", {}).get("total", 0) if isinstance(meta.get("signatures"), dict) else 0,
        meta.get("allowlist_suppressed", 0),
        json.dumps(summary.get("by_category", {})),
        meta.get("scanner_version", ""),
        json.dumps(summary),
    ))
    conn.commit()

    if close_conn:
        conn.close()

    return True


def show_history(plugin_name=None, limit=20, conn=None):
    """Show scan history for a plugin or all plugins."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    if plugin_name:
        cursor = conn.execute("""
            SELECT timestamp, plugin_name, overall_risk, total_findings,
                   critical_count, high_count, medium_count, files_scanned, signatures_total
            FROM scan_history
            WHERE plugin_name LIKE ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (f"%{plugin_name}%", limit))
    else:
        cursor = conn.execute("""
            SELECT timestamp, plugin_name, overall_risk, total_findings,
                   critical_count, high_count, medium_count, files_scanned, signatures_total
            FROM scan_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()

    if close_conn:
        conn.close()

    return rows


def get_trends(conn=None):
    """Detect risk level changes over time for each plugin."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    # Get the two most recent scans for each plugin
    cursor = conn.execute("""
        SELECT plugin_name, overall_risk, total_findings, timestamp,
               ROW_NUMBER() OVER (PARTITION BY plugin_name ORDER BY timestamp DESC) as rn
        FROM scan_history
    """)

    rows = cursor.fetchall()

    if close_conn:
        conn.close()

    # Group by plugin
    by_plugin = {}
    for row in rows:
        name = row[0]
        rn = row[4]
        if name not in by_plugin:
            by_plugin[name] = {}
        if rn <= 2:
            by_plugin[name][rn] = {
                "risk": row[1],
                "findings": row[2],
                "timestamp": row[3]
            }

    # Find changes
    changes = []
    for name, scans in by_plugin.items():
        if 1 in scans and 2 in scans:
            current = scans[1]
            previous = scans[2]
            if current["risk"] != previous["risk"]:
                risk_order = {"SAFE": 0, "CAUTION": 1, "DANGER": 2}
                direction = "DEGRADED" if risk_order.get(current["risk"], 0) > risk_order.get(previous["risk"], 0) else "IMPROVED"
                changes.append({
                    "plugin": name,
                    "direction": direction,
                    "previous_risk": previous["risk"],
                    "current_risk": current["risk"],
                    "previous_findings": previous["findings"],
                    "current_findings": current["findings"],
                    "previous_scan": previous["timestamp"],
                    "current_scan": current["timestamp"],
                })

    return changes


def get_stats(conn=None):
    """Get overall statistics."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    stats = {}

    cursor = conn.execute("SELECT COUNT(*) FROM scan_history")
    stats["total_scans"] = cursor.fetchone()[0]

    cursor = conn.execute("SELECT COUNT(DISTINCT plugin_name) FROM scan_history")
    stats["unique_plugins"] = cursor.fetchone()[0]

    cursor = conn.execute("""
        SELECT overall_risk, COUNT(*) FROM scan_history GROUP BY overall_risk
    """)
    stats["by_risk"] = {row[0]: row[1] for row in cursor.fetchall()}

    cursor = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM scan_history")
    row = cursor.fetchone()
    stats["first_scan"] = row[0]
    stats["last_scan"] = row[1]

    if close_conn:
        conn.close()

    return stats


def prune_old(days, conn=None):
    """Delete entries older than N days."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    cursor = conn.execute("DELETE FROM scan_history WHERE timestamp < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()

    if close_conn:
        conn.close()

    return deleted


def export_all(conn=None):
    """Export all history as JSON."""
    close_conn = False
    if conn is None:
        conn = init_db()
        close_conn = True

    cursor = conn.execute("""
        SELECT timestamp, plugin_name, plugin_path, overall_risk, total_findings,
               critical_count, high_count, medium_count, low_count, info_count,
               files_scanned, signatures_total, scanner_version
        FROM scan_history
        ORDER BY timestamp DESC
    """)

    rows = cursor.fetchall()

    if close_conn:
        conn.close()

    return [{
        "timestamp": r[0], "plugin_name": r[1], "plugin_path": r[2],
        "overall_risk": r[3], "total_findings": r[4],
        "critical": r[5], "high": r[6], "medium": r[7], "low": r[8], "info": r[9],
        "files_scanned": r[10], "signatures_total": r[11], "scanner_version": r[12]
    } for r in rows]


def format_history_table(rows):
    """Format history rows as a readable table."""
    if not rows:
        return "No scan history found."

    lines = []
    lines.append(f"{'Timestamp':19s} | {'Plugin':25s} | {'Risk':7s} | {'Findings':8s} | {'CRIT':4s} | {'HIGH':4s} | {'MED':4s} | {'Sigs':4s}")
    lines.append("-" * 100)

    for row in rows:
        ts = row[0][:19].replace("T", " ") if row[0] else "?"
        lines.append(f"{ts:19s} | {row[1]:25s} | {row[2]:7s} | {row[3]:8d} | {row[4]:4d} | {row[5]:4d} | {row[6]:4d} | {row[8]:4d}")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: scan_history.py <command> [args]",
            "commands": {
                "--save <json-file-or-stdin>": "Save a scan result to history",
                "--show [plugin-name]": "Show recent history (optional filter)",
                "--show-all": "Show all history",
                "--trends": "Show risk level changes",
                "--stats": "Show overall statistics",
                "--export": "Export all history as JSON",
                "--prune <days>": "Delete entries older than N days"
            }
        }, indent=2))
        sys.exit(0)

    command = sys.argv[1]

    if command == "--save":
        # Read report from file or stdin
        if len(sys.argv) > 2 and os.path.isfile(sys.argv[2]):
            with open(sys.argv[2], "r") as f:
                report = json.load(f)
        else:
            report = json.loads(sys.stdin.read())

        save_scan(report)
        plugin_name = Path(report.get("scan_metadata", {}).get("target", "")).name
        print(f"Saved scan result for '{plugin_name}' to history.")

    elif command == "--show":
        plugin_filter = sys.argv[2] if len(sys.argv) > 2 else None
        rows = show_history(plugin_filter)
        print(format_history_table(rows))

    elif command == "--show-all":
        rows = show_history(limit=1000)
        print(format_history_table(rows))

    elif command == "--trends":
        changes = get_trends()
        if not changes:
            print("No risk level changes detected.")
        else:
            for c in changes:
                icon = "!!!" if c["direction"] == "DEGRADED" else "+++"
                print(f"{icon} {c['plugin']}: {c['previous_risk']} -> {c['current_risk']} "
                      f"({c['previous_findings']} -> {c['current_findings']} findings)")

    elif command == "--stats":
        stats = get_stats()
        print(json.dumps(stats, indent=2))

    elif command == "--export":
        data = export_all()
        print(json.dumps(data, indent=2))

    elif command == "--prune":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 90
        deleted = prune_old(days)
        print(f"Pruned {deleted} entries older than {days} days.")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

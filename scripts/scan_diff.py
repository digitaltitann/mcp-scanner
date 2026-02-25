#!/usr/bin/env python3
"""
Diff Scanner — scan only changed files in a plugin.

Detects which files have changed since the last scan (using the gate scan
checksum state or git diff) and runs the security scanner only on those files.
Highlights NEW threats that weren't present before.

Usage:
    python scan_diff.py <path-to-plugin>
    python scan_diff.py <path-to-plugin> --since HEAD~1
    python scan_diff.py <path-to-plugin> --since 2026-02-01
Output: JSON report to stdout
"""

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = os.path.expanduser("~/.claude/mcp-scanner-state.json")


def load_gate_state():
    """Load the gate scan checksum state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"checksums": {}, "last_scan": None}


def get_git_changed_files(plugin_dir, since=None):
    """Get files changed in git since a reference point."""
    try:
        # Check if it's a git repo
        result = subprocess.run(
            ["git", "-C", str(plugin_dir), "rev-parse", "--git-dir"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None  # Not a git repo

        if since:
            # Use git diff against a reference
            result = subprocess.run(
                ["git", "-C", str(plugin_dir), "diff", "--name-only", since],
                capture_output=True, text=True, timeout=10
            )
        else:
            # Show all modified and untracked files
            result = subprocess.run(
                ["git", "-C", str(plugin_dir), "status", "--porcelain"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                files = []
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        # Status is first 2 chars, then space, then filename
                        fname = line[3:].strip()
                        if fname:
                            files.append(fname)
                return files

        if result.returncode == 0:
            return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]

    except (subprocess.TimeoutExpired, OSError):
        pass

    return None


def compute_file_hash(file_path):
    """Compute SHA-256 hash of a single file."""
    try:
        content = Path(file_path).read_bytes()
        return hashlib.sha256(content).hexdigest()
    except (OSError, IOError):
        return None


def find_changed_files_by_checksum(plugin_dir, stored_hashes):
    """Find files that changed by comparing individual file hashes."""
    changed = []
    new_hashes = {}
    plugin_path = Path(plugin_dir)

    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
    skip_exts = {".exe", ".dll", ".so", ".pyc", ".pyo", ".png", ".jpg", ".gif", ".zip"}

    for root, dirs, files in os.walk(str(plugin_path)):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in skip_exts:
                continue

            rel_path = str(fpath.relative_to(plugin_path))
            file_hash = compute_file_hash(fpath)
            if file_hash:
                new_hashes[rel_path] = file_hash
                old_hash = stored_hashes.get(rel_path)
                if old_hash != file_hash:
                    changed.append(rel_path)

    # Also detect deleted files
    deleted = [f for f in stored_hashes if f not in new_hashes]

    return changed, deleted, new_hashes


def scan_changed_files(plugin_dir, changed_files):
    """Run the scanner on the plugin but report only findings in changed files."""
    scanner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_plugin.py")

    try:
        result = subprocess.run(
            [sys.executable, scanner_path, str(plugin_dir)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        full_report = json.loads(result.stdout)

        # Normalize changed file paths for matching
        plugin_path = Path(plugin_dir).resolve()
        changed_set = set()
        for cf in changed_files:
            # Build the full path for comparison
            full_cf = str(plugin_path / cf)
            changed_set.add(full_cf.replace("/", os.sep).replace("\\", os.sep))
            changed_set.add(full_cf.replace("\\", "/"))
            changed_set.add(full_cf)

        # Filter findings to only those in changed files
        diff_findings = []
        other_findings = []
        for finding in full_report.get("findings", []):
            fpath = finding.get("file", "")
            fpath_normalized = fpath.replace("\\", "/")
            if fpath in changed_set or fpath_normalized in changed_set:
                finding["diff_status"] = "CHANGED"
                diff_findings.append(finding)
            else:
                other_findings.append(finding)

        return full_report, diff_findings, other_findings

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: scan_diff.py <path-to-plugin> [--since <ref>]",
            "examples": [
                "python scan_diff.py ~/.claude/plugins/my-plugin",
                "python scan_diff.py ~/.claude/plugins/my-plugin --since HEAD~1",
            ]
        }, indent=2))
        sys.exit(0)

    target = sys.argv[1]
    since = None
    if "--since" in sys.argv:
        idx = sys.argv.index("--since")
        if idx + 1 < len(sys.argv):
            since = sys.argv[idx + 1]

    plugin_dir = Path(target).resolve()
    if not plugin_dir.is_dir():
        print(json.dumps({"error": f"Not a directory: {target}"}))
        sys.exit(1)

    # Strategy 1: Use git diff if available
    changed_files = get_git_changed_files(plugin_dir, since)

    if changed_files is None:
        # Strategy 2: Use stored file hashes from scan history
        state = load_gate_state()
        plugin_key = str(plugin_dir)
        stored_data = state.get("file_hashes", {}).get(plugin_key, {})
        changed_files, deleted_files, new_hashes = find_changed_files_by_checksum(plugin_dir, stored_data)

        if not changed_files and not deleted_files:
            print(json.dumps({
                "scan_metadata": {
                    "target": str(plugin_dir),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "scanner": "diff-scanner",
                    "method": "checksum",
                },
                "diff_summary": {
                    "changed_files": 0,
                    "deleted_files": 0,
                    "status": "NO_CHANGES"
                },
                "summary": {
                    "overall_risk": "SAFE",
                    "total_findings": 0,
                    "note": "No files have changed since last scan"
                },
                "findings": []
            }, indent=2))
            sys.exit(0)

    if not changed_files:
        print(json.dumps({
            "scan_metadata": {
                "target": str(plugin_dir),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scanner": "diff-scanner",
                "method": "git" if since else "checksum",
            },
            "diff_summary": {
                "changed_files": 0,
                "status": "NO_CHANGES"
            },
            "summary": {
                "overall_risk": "SAFE",
                "total_findings": 0,
                "note": "No files have changed"
            },
            "findings": []
        }, indent=2))
        sys.exit(0)

    # Scan and filter
    result = scan_changed_files(plugin_dir, changed_files)
    if result is None:
        print(json.dumps({"error": "Scanner failed"}))
        sys.exit(1)

    full_report, diff_findings, other_findings = result

    # Determine risk for changed files only
    severity_counts = {}
    category_counts = {}
    for f in diff_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

    if severity_counts.get("CRITICAL", 0) > 0:
        diff_risk = "DANGER"
    elif severity_counts.get("HIGH", 0) >= 3:
        diff_risk = "DANGER"
    elif severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) > 0:
        diff_risk = "CAUTION"
    else:
        diff_risk = "SAFE"

    report = {
        "scan_metadata": {
            "target": str(plugin_dir),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": "diff-scanner",
            "method": "git" if since else "checksum",
            "full_scan_signatures": full_report.get("scan_metadata", {}).get("signatures", {}),
        },
        "diff_summary": {
            "changed_files": len(changed_files),
            "changed_file_list": changed_files[:50],
            "findings_in_changed": len(diff_findings),
            "findings_in_unchanged": len(other_findings),
            "full_scan_findings": full_report.get("summary", {}).get("total_findings", 0),
        },
        "summary": {
            "overall_risk": diff_risk,
            "total_findings": len(diff_findings),
            "by_severity": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
                "INFO": severity_counts.get("INFO", 0),
            },
            "by_category": category_counts,
            "note": f"Showing only findings in {len(changed_files)} changed file(s)"
        },
        "findings": diff_findings
    }

    print(json.dumps(report, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Remote Scanner — scan a GitHub repository without cloning it.

Uses the GitHub API (via `gh`) to list repo files and fetches content
via raw.githubusercontent.com. Runs the same pattern-based analysis
as the local scanner but without touching the filesystem.

Usage:
    python scan_remote.py <github-url-or-owner/repo>
    python scan_remote.py https://github.com/user/plugin
    python scan_remote.py user/plugin
    python scan_remote.py user/plugin --branch dev
Output: JSON report to stdout
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
                   ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp",
                   ".mp3", ".mp4", ".wav", ".zip", ".tar", ".gz", ".7z",
                   ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf"}
MAX_FILE_SIZE = 1_048_576  # 1 MB


def parse_github_url(url_or_slug):
    """Extract owner/repo from GitHub URL or slug."""
    url_or_slug = url_or_slug.strip().rstrip("/")

    # Handle full URLs
    match = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', url_or_slug)
    if match:
        return match.group(1), match.group(2)

    # Handle owner/repo format
    match = re.match(r'^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)$', url_or_slug)
    if match:
        return match.group(1), match.group(2)

    return None, None


def get_repo_tree(owner, repo, branch="HEAD"):
    """Get the file tree of a repo using gh API."""
    try:
        # First get the default branch if HEAD
        if branch == "HEAD":
            result = subprocess.run(
                ["gh", "api", f"repos/{owner}/{repo}", "--jq", ".default_branch"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                branch = result.stdout.strip()
            else:
                branch = "main"

        # Get the tree recursively
        result = subprocess.run(
            ["gh", "api", f"repos/{owner}/{repo}/git/trees/{branch}?recursive=1"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return None, branch, f"GitHub API error: {result.stderr.strip()}"

        data = json.loads(result.stdout)
        return data, branch, None

    except subprocess.TimeoutExpired:
        return None, branch, "GitHub API request timed out"
    except (json.JSONDecodeError, OSError) as e:
        return None, branch, str(e)


def fetch_file_content(owner, repo, branch, file_path):
    """Fetch a single file's content from GitHub."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
    try:
        req = Request(url, headers={"User-Agent": "mcp-scanner/2.0"})
        with urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (URLError, HTTPError, OSError):
        return None


def filter_scannable_files(tree_data):
    """Filter the tree to only scannable files."""
    files = []
    if not tree_data or "tree" not in tree_data:
        return files

    for item in tree_data["tree"]:
        if item.get("type") != "blob":
            continue

        path = item.get("path", "")
        size = item.get("size", 0)

        # Skip oversized files
        if size > MAX_FILE_SIZE:
            continue

        # Skip files in excluded directories
        parts = path.split("/")
        if any(p in SKIP_DIRS for p in parts):
            continue

        # Skip binary/media extensions
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            continue

        files.append({"path": path, "size": size, "ext": ext})

    return files


def scan_remote_repo(owner, repo, branch="HEAD"):
    """Scan a remote GitHub repo without cloning."""
    # Get the file tree
    tree_data, actual_branch, error = get_repo_tree(owner, repo, branch)
    if error:
        return {"error": error}

    # Filter to scannable files
    scannable = filter_scannable_files(tree_data)

    if not scannable:
        return {
            "scan_metadata": {
                "target": f"github.com/{owner}/{repo}",
                "branch": actual_branch,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scanner": "remote-scanner",
                "files_scanned": 0,
            },
            "summary": {
                "overall_risk": "SAFE",
                "total_findings": 0,
                "by_severity": {},
                "by_category": {}
            },
            "findings": []
        }

    # Create a temp directory, download files, and run the scanner
    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmpdir:
        downloaded = 0
        for file_info in scannable:
            content = fetch_file_content(owner, repo, actual_branch, file_info["path"])
            if content is None:
                continue

            # Write to temp directory preserving path structure
            dest = Path(tmpdir) / file_info["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            downloaded += 1

        if downloaded == 0:
            return {"error": "Could not download any files from the repository"}

        # Run the scanner on the temp directory
        scanner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_plugin.py")
        try:
            result = subprocess.run(
                [sys.executable, scanner_path, tmpdir],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                report = json.loads(result.stdout)
                # Override the target to show the GitHub URL
                report["scan_metadata"]["target"] = f"github.com/{owner}/{repo}"
                report["scan_metadata"]["branch"] = actual_branch
                report["scan_metadata"]["remote_scan"] = True
                report["scan_metadata"]["files_downloaded"] = downloaded

                # Fix file paths in findings to show repo paths instead of temp paths
                for finding in report.get("findings", []):
                    fpath = finding.get("file", "")
                    # Strip the temp dir prefix
                    if tmpdir in fpath:
                        rel = fpath[len(tmpdir):].lstrip(os.sep).lstrip("/")
                        finding["file"] = f"{owner}/{repo}/{rel}"

                return report
            else:
                return {"error": f"Scanner failed: {result.stderr.strip()}"}

        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out"}
        except (json.JSONDecodeError, OSError) as e:
            return {"error": f"Scanner error: {e}"}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: scan_remote.py <github-url-or-owner/repo> [--branch <branch>]",
            "examples": [
                "python scan_remote.py user/plugin",
                "python scan_remote.py https://github.com/user/plugin",
                "python scan_remote.py user/plugin --branch dev"
            ]
        }, indent=2))
        sys.exit(0)

    target = sys.argv[1]
    branch = "HEAD"
    if "--branch" in sys.argv:
        idx = sys.argv.index("--branch")
        if idx + 1 < len(sys.argv):
            branch = sys.argv[idx + 1]

    owner, repo = parse_github_url(target)
    if not owner or not repo:
        print(json.dumps({"error": f"Could not parse GitHub URL: {target}"}))
        sys.exit(1)

    use_markdown = "--markdown" in sys.argv

    report = scan_remote_repo(owner, repo, branch)

    if use_markdown and "error" not in report:
        # Import format_markdown from scan_plugin
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from scan_plugin import format_markdown
        print(format_markdown(report))
    else:
        print(json.dumps(report, indent=2))

    sys.exit(0)


if __name__ == "__main__":
    main()

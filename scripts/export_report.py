#!/usr/bin/env python3
"""
Report Exporter — converts MCP Scanner JSON reports to formatted markdown.

Reads a JSON scan report from stdin or a file and outputs a markdown document
suitable for sharing, archiving, or review.

Usage:
    python scan_plugin.py <path> | python export_report.py          # Pipe from scanner
    python export_report.py report.json                              # From file
    python export_report.py report.json -o report.md                 # Save to file
"""

import json
import sys
from datetime import datetime
from pathlib import Path


SEVERITY_ICONS = {
    "CRITICAL": "!!!",
    "HIGH": "!!",
    "MEDIUM": "!",
    "LOW": "~",
    "INFO": "i",
}

RISK_LABELS = {
    "SAFE": "SAFE — No threats detected",
    "CAUTION": "CAUTION — Review recommended",
    "DANGER": "DANGER — Critical threats found",
}


def format_markdown(report):
    """Convert a scan report dict to formatted markdown."""
    lines = []

    meta = report.get("scan_metadata", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    target = meta.get("target", "Unknown")
    target_name = Path(target).name if target != "Unknown" else target
    timestamp = meta.get("timestamp", "")[:19].replace("T", " ")
    version = meta.get("scanner_version", "?")
    files_scanned = meta.get("files_scanned", 0)
    sigs = meta.get("signatures", {})

    overall_risk = summary.get("overall_risk", "UNKNOWN")
    total_findings = summary.get("total_findings", 0)
    by_severity = summary.get("by_severity", {})
    by_category = summary.get("by_category", {})

    # Header
    lines.append(f"# Security Scan Report: {target_name}")
    lines.append("")
    lines.append(f"**Overall Risk: {overall_risk}** — {RISK_LABELS.get(overall_risk, '')}")
    lines.append("")

    # Metadata table
    lines.append("## Scan Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Target | `{target}` |")
    lines.append(f"| Scanned | {timestamp} UTC |")
    lines.append(f"| Scanner | MCP Scanner v{version} |")
    lines.append(f"| Files scanned | {files_scanned} |")
    if sigs:
        total_sigs = sigs.get("total", "?")
        ext_p = sigs.get("external_patterns", 0)
        ext_m = sigs.get("external_malicious", 0)
        lines.append(f"| Signatures | {total_sigs} total ({ext_p} external patterns, {ext_m} external malicious) |")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**{total_findings} findings** across {len(by_category)} categories:")
    lines.append("")

    # Severity breakdown
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")
    lines.append("")

    # Category breakdown
    if by_category:
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        lines.append("")

        current_severity = None
        for finding in findings:
            sev = finding.get("severity", "UNKNOWN")
            if sev != current_severity:
                current_severity = sev
                lines.append(f"### {sev}")
                lines.append("")

            fid = finding.get("id", "?")
            pattern_id = finding.get("pattern_id", "?")
            desc = finding.get("description", "")
            file_path = finding.get("file", "")
            line_num = finding.get("line", 0)
            line_content = finding.get("line_content", "")
            context = finding.get("context_note", "")
            category = finding.get("category", "")

            lines.append(f"**{fid}. [{pattern_id}] {desc}**")
            lines.append("")
            lines.append(f"- **Category:** {category}")
            if file_path:
                file_display = Path(file_path).name
                lines.append(f"- **File:** `{file_path}` (line {line_num})")
            if line_content:
                lines.append(f"- **Code:** `{line_content[:120]}`")
            if context:
                lines.append(f"- **Context:** {context}")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security findings detected. This plugin appears safe.")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")

    if overall_risk == "DANGER":
        known_malicious = by_category.get("known-malicious", 0)
        if known_malicious > 0:
            lines.append(f"- **{known_malicious} known malicious signature(s) matched** — DO NOT install this plugin")
        lines.append("- This plugin has critical security issues requiring immediate attention")
        lines.append("- Manual review of all CRITICAL findings is strongly recommended")
        lines.append("- Consider removing this plugin if already installed")
    elif overall_risk == "CAUTION":
        lines.append("- Review the flagged files manually before trusting this plugin")
        lines.append("- Some findings may be false positives — check context notes")
        lines.append("- Consider adding confirmed false positives to the allowlist")
    else:
        lines.append("- No action required — this plugin passed all security checks")
        lines.append("- Periodic rescanning is recommended after plugin updates")

    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by MCP Scanner v{version}*")

    return "\n".join(lines)


def main():
    # Read from file argument or stdin
    if len(sys.argv) > 1 and sys.argv[1] != "-o":
        input_path = sys.argv[1]
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            report = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON from stdin: {e}", file=sys.stderr)
            sys.exit(1)

    # Check for errors
    if "error" in report:
        print(f"Scanner error: {report['error']}", file=sys.stderr)
        sys.exit(1)

    markdown = format_markdown(report)

    # Output to file or stdout
    output_path = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output_path = sys.argv[idx + 1]

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"Report saved to: {output_path}", file=sys.stderr)
    else:
        print(markdown)


if __name__ == "__main__":
    main()

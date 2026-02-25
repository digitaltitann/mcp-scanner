#!/usr/bin/env python3
"""
SARIF Exporter — convert MCP Scanner JSON reports to SARIF 2.1.0 format.

SARIF (Static Analysis Results Interchange Format) is the industry standard
for static analysis tools. Output integrates with GitHub Code Scanning,
VS Code SARIF Viewer, and other security platforms.

Usage:
    python scan_plugin.py <path> | python export_sarif.py
    python export_sarif.py <json-report-file>
    python export_sarif.py <json-report-file> -o report.sarif
Output: SARIF 2.1.0 JSON to stdout or file
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

# Map MCP Scanner severities to SARIF levels
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Map MCP Scanner categories to SARIF rule help URLs
CATEGORY_HELP = {
    "prompt-injection": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "data-exfiltration": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "code-execution": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "credential-theft": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "network-abuse": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "obfuscation": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "filesystem-abuse": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "over-broad-permissions": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "hook-hijacking": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "known-malicious": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
    "rug-pull": "https://github.com/digitaltitann/mcp-scanner#what-it-detects",
}


def convert_to_sarif(report):
    """Convert an MCP Scanner JSON report to SARIF 2.1.0 format."""
    meta = report.get("scan_metadata", {})
    findings = report.get("findings", [])

    # Build rules from unique pattern IDs
    rules = {}
    for finding in findings:
        pid = finding.get("pattern_id", "UNKNOWN")
        if pid not in rules:
            category = finding.get("category", "unknown")
            rules[pid] = {
                "id": pid,
                "name": pid,
                "shortDescription": {
                    "text": finding.get("description", pid)
                },
                "fullDescription": {
                    "text": finding.get("context_note", finding.get("description", ""))
                },
                "helpUri": CATEGORY_HELP.get(category, "https://github.com/digitaltitann/mcp-scanner"),
                "properties": {
                    "category": category,
                    "severity": finding.get("severity", "MEDIUM"),
                    "tags": [category]
                }
            }

    # Build results
    results = []
    for finding in findings:
        line = finding.get("line", 1)
        if line < 1:
            line = 1

        result = {
            "ruleId": finding.get("pattern_id", "UNKNOWN"),
            "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "MEDIUM"), "warning"),
            "message": {
                "text": finding.get("description", "Security finding")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get("file", "").replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": line,
                        "startColumn": 1,
                        "snippet": {
                            "text": finding.get("line_content", "")
                        }
                    }
                }
            }],
            "properties": {
                "severity": finding.get("severity", "MEDIUM"),
                "category": finding.get("category", "unknown"),
            }
        }

        if finding.get("context_note"):
            result["properties"]["contextNote"] = finding["context_note"]

        results.append(result)

    # Determine invocation status
    summary = report.get("summary", {})
    overall_risk = summary.get("overall_risk", "UNKNOWN")

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCP Scanner",
                    "version": meta.get("scanner_version", "unknown"),
                    "informationUri": "https://github.com/digitaltitann/mcp-scanner",
                    "rules": list(rules.values()),
                    "properties": {
                        "signatures": meta.get("signatures", {}),
                    }
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "properties": {
                    "overallRisk": overall_risk,
                    "filesScanned": meta.get("files_scanned", 0),
                    "allowlistSuppressed": meta.get("allowlist_suppressed", 0),
                }
            }],
            "results": results,
            "properties": {
                "overallRisk": overall_risk,
                "totalFindings": summary.get("total_findings", 0),
                "bySeverity": summary.get("by_severity", {}),
                "byCategory": summary.get("by_category", {}),
            }
        }]
    }

    return sarif


def main():
    # Read report from file argument or stdin
    if len(sys.argv) > 1 and sys.argv[1] != "-o" and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            report = json.load(f)
    else:
        try:
            report = json.loads(sys.stdin.read())
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Invalid JSON input: {e}"}), file=sys.stderr)
            sys.exit(1)

    sarif = convert_to_sarif(report)

    # Output
    output_file = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]

    sarif_json = json.dumps(sarif, indent=2)

    if output_file:
        Path(output_file).write_text(sarif_json, encoding="utf-8")
        print(f"SARIF report written to: {output_file}")
    else:
        print(sarif_json)


if __name__ == "__main__":
    main()

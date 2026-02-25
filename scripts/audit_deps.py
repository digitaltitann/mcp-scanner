#!/usr/bin/env python3
"""
Dependency Auditor — checks plugin dependencies for security risks.

Analyzes package.json (npm) and requirements.txt / pyproject.toml (Python)
for suspicious packages, typosquatting, dangerous install scripts, and
overly permissive version ranges.

Usage:
    python audit_deps.py <path-to-plugin>
Output: JSON report to stdout
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Popular packages and their common typosquatting targets
TYPOSQUAT_TARGETS = {
    # npm
    "lodash": ["lodahs", "lodashs", "l0dash", "1odash", "lodash-es-fake"],
    "express": ["expres", "expresss", "exppress", "expreses"],
    "react": ["reakt", "raect", "reactt", "r3act"],
    "axios": ["axois", "axio", "axioss", "axi0s"],
    "chalk": ["chalks", "chalkk", "cha1k"],
    "moment": ["momnet", "monment", "m0ment"],
    "commander": ["comander", "commanderr"],
    "debug": ["debugg", "debub"],
    "dotenv": ["dot-env", "dotnev", "dotenvv"],
    "webpack": ["webpak", "webpackk", "w3bpack"],
    "typescript": ["typescipt", "typscript", "typescrip"],
    "eslint": ["es1int", "eslintt"],
    # pip
    "requests": ["reqeusts", "requsets", "reqests", "request", "requestes"],
    "flask": ["falsk", "flaask", "f1ask"],
    "django": ["djano", "dajngo", "djang0"],
    "numpy": ["numby", "numppy", "num-py"],
    "pandas": ["pandsa", "pands", "panads"],
    "urllib3": ["urllib4", "urlib3", "urllib33"],
    "cryptography": ["cyptography", "crytography", "cryptograpy"],
    "paramiko": ["parmiko", "paramko", "paramik0"],
    "boto3": ["b0to3", "botto3", "boto33"],
    "pyyaml": ["pyaml", "pyyml", "pyyam1"],
}

# Known malicious package names (from security advisories)
KNOWN_MALICIOUS_PACKAGES = {
    # npm
    "event-stream-malicious", "flatmap-stream", "ua-parser-js-malicious",
    "colors-malicious", "faker-malicious",
    # pip
    "python3-dateutil", "jeIlyfish", "python-binance-sdk",
    "acqusition", "apidev-coop", "baborern",
    "coloUrama", "djang0", "djangoo",
}

# Suspicious patterns in package names
SUSPICIOUS_NAME_PATTERNS = [
    (re.compile(r'^(?:evil|malware|hack|exploit|backdoor|trojan|keylog|stealer|exfil)', re.IGNORECASE),
     "Package name starts with a suspicious word"),
    (re.compile(r'(?:reverse.?shell|bind.?shell|rat[_\-.]|c2[_\-.]|beacon)', re.IGNORECASE),
     "Package name suggests malicious tool"),
    (re.compile(r'(?:mcp|claude|anthropic).*(?:hack|exploit|evil|inject)', re.IGNORECASE),
     "Package name targets Claude/MCP with suspicious intent"),
]


def check_typosquatting(package_name):
    """Check if a package name looks like a typosquat of a popular package."""
    name_lower = package_name.lower().strip()
    findings = []

    for legit_name, typos in TYPOSQUAT_TARGETS.items():
        if name_lower in typos:
            findings.append({
                "severity": "CRITICAL",
                "category": "typosquatting",
                "package": package_name,
                "description": f"'{package_name}' is a known typosquat of '{legit_name}'",
                "recommendation": f"Use '{legit_name}' instead"
            })

    # Check Levenshtein-like similarity (simple edit distance check)
    for legit_name in TYPOSQUAT_TARGETS:
        if name_lower == legit_name:
            continue
        if len(name_lower) == len(legit_name):
            diffs = sum(1 for a, b in zip(name_lower, legit_name) if a != b)
            if diffs == 1:
                findings.append({
                    "severity": "HIGH",
                    "category": "typosquatting",
                    "package": package_name,
                    "description": f"'{package_name}' is 1 character away from popular package '{legit_name}'",
                    "recommendation": f"Verify this is the intended package, not a typosquat of '{legit_name}'"
                })

    return findings


def check_package_name(package_name):
    """Check a package name for suspicious patterns."""
    findings = []

    # Known malicious
    if package_name.lower() in KNOWN_MALICIOUS_PACKAGES:
        findings.append({
            "severity": "CRITICAL",
            "category": "known-malicious",
            "package": package_name,
            "description": f"'{package_name}' is a known malicious package",
            "recommendation": "Remove this package immediately"
        })

    # Suspicious name patterns
    for pattern, reason in SUSPICIOUS_NAME_PATTERNS:
        if pattern.search(package_name):
            findings.append({
                "severity": "HIGH",
                "category": "suspicious-name",
                "package": package_name,
                "description": f"'{package_name}': {reason}",
                "recommendation": "Investigate this package before using"
            })

    # Typosquatting check
    findings.extend(check_typosquatting(package_name))

    return findings


def audit_package_json(file_path):
    """Audit an npm package.json file."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        return [{"severity": "MEDIUM", "category": "parse-error",
                 "description": f"Could not parse {file_path}: {e}",
                 "file": str(file_path)}]

    # Check all dependency sections
    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
    all_deps = {}
    for section in dep_sections:
        deps = data.get(section, {})
        if isinstance(deps, dict):
            all_deps.update(deps)

    # Check each package name
    for pkg_name, version_spec in all_deps.items():
        pkg_findings = check_package_name(pkg_name)
        for f in pkg_findings:
            f["file"] = str(file_path)
            f["version"] = str(version_spec)
        findings.extend(pkg_findings)

        # Check for git/URL dependencies (can point to malicious repos)
        if isinstance(version_spec, str):
            if version_spec.startswith("git") or version_spec.startswith("http"):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "url-dependency",
                    "package": pkg_name,
                    "description": f"'{pkg_name}' uses a Git/URL dependency: {version_spec[:80]}",
                    "recommendation": "URL dependencies bypass the npm registry — verify the source",
                    "file": str(file_path),
                    "version": version_spec
                })

            # Wildcard version
            if version_spec in ("*", "latest", ""):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "version-range",
                    "package": pkg_name,
                    "description": f"'{pkg_name}' uses wildcard version '{version_spec}'",
                    "recommendation": "Pin to a specific version to prevent supply chain attacks",
                    "file": str(file_path),
                    "version": version_spec
                })

    # Check for suspicious install scripts
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for script_name in ["preinstall", "install", "postinstall"]:
            script_cmd = scripts.get(script_name, "")
            if not isinstance(script_cmd, str):
                continue

            # Check for network access in install scripts
            if re.search(r'(?:curl|wget|fetch|http|nc\s|netcat)', script_cmd, re.IGNORECASE):
                findings.append({
                    "severity": "HIGH",
                    "category": "install-script",
                    "description": f"Install script '{script_name}' makes network calls",
                    "detail": f"Command: {script_cmd[:150]}",
                    "recommendation": "Install scripts should not download external resources",
                    "file": str(file_path)
                })

            # Check for code execution in install scripts
            if re.search(r'(?:eval|exec|node\s+-e|python\s+-c)', script_cmd, re.IGNORECASE):
                findings.append({
                    "severity": "HIGH",
                    "category": "install-script",
                    "description": f"Install script '{script_name}' executes dynamic code",
                    "detail": f"Command: {script_cmd[:150]}",
                    "recommendation": "Install scripts should not execute dynamic code",
                    "file": str(file_path)
                })

    return findings


def audit_requirements_txt(file_path):
    """Audit a Python requirements.txt file."""
    findings = []

    try:
        content = Path(file_path).read_text(encoding="utf-8")
    except IOError:
        return []

    for line_num, line in enumerate(content.split("\n"), start=1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Extract package name (before version specifier)
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
        if not match:
            continue

        pkg_name = match.group(1)
        pkg_findings = check_package_name(pkg_name)
        for f in pkg_findings:
            f["file"] = str(file_path)
            f["line"] = line_num
        findings.extend(pkg_findings)

        # Check for non-PyPI index URLs
        if "--index-url" in line or "--extra-index-url" in line:
            findings.append({
                "severity": "HIGH",
                "category": "custom-index",
                "description": f"Custom package index in requirements: {line[:100]}",
                "recommendation": "Custom indexes can serve malicious packages — verify the source",
                "file": str(file_path),
                "line": line_num
            })

    return findings


def audit_pyproject_toml(file_path):
    """Audit a Python pyproject.toml file for dependencies."""
    findings = []

    try:
        content = Path(file_path).read_text(encoding="utf-8")
    except IOError:
        return []

    # Simple TOML parsing for dependencies (avoid external dependency)
    in_deps_section = False
    for line_num, line in enumerate(content.split("\n"), start=1):
        stripped = line.strip()

        if stripped in ("[project.dependencies]", "[tool.poetry.dependencies]",
                        "[project.optional-dependencies]"):
            in_deps_section = True
            continue
        elif stripped.startswith("["):
            in_deps_section = False
            continue

        if in_deps_section:
            # Match: "package-name" or package = "..."
            match = re.match(r'^["\']?([a-zA-Z0-9_\-\.]+)', stripped)
            if match:
                pkg_name = match.group(1)
                if pkg_name in ("python", "name", "version", "description"):
                    continue
                pkg_findings = check_package_name(pkg_name)
                for f in pkg_findings:
                    f["file"] = str(file_path)
                    f["line"] = line_num
                findings.extend(pkg_findings)

    return findings


def audit_plugin(target_dir):
    """Audit all dependency files in a plugin directory."""
    target = Path(target_dir)
    all_findings = []
    files_checked = []

    # Find and audit package.json files
    for pj in target.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in str(pj):
            continue
        files_checked.append(str(pj))
        all_findings.extend(audit_package_json(pj))

    # Find and audit requirements files
    for pattern in ["requirements.txt", "requirements*.txt", "constraints.txt"]:
        for req in target.rglob(pattern):
            files_checked.append(str(req))
            all_findings.extend(audit_requirements_txt(req))

    # Find and audit pyproject.toml files
    for pp in target.rglob("pyproject.toml"):
        files_checked.append(str(pp))
        all_findings.extend(audit_pyproject_toml(pp))

    # Find and audit setup.py (check for suspicious install code)
    for sp in target.rglob("setup.py"):
        files_checked.append(str(sp))
        try:
            content = sp.read_text(encoding="utf-8", errors="replace")
            if re.search(r'(?:urllib|requests|socket|subprocess)', content):
                if re.search(r'(?:urlopen|requests\.\w+|\.connect|Popen|check_output)', content):
                    all_findings.append({
                        "severity": "HIGH",
                        "category": "install-script",
                        "description": "setup.py contains network or subprocess calls",
                        "recommendation": "setup.py should not make network calls or run subprocesses during installation",
                        "file": str(sp)
                    })
        except IOError:
            pass

    # Determine severity counts
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts.get("CRITICAL", 0) > 0:
        overall_risk = "DANGER"
    elif severity_counts.get("HIGH", 0) > 0:
        overall_risk = "CAUTION"
    elif severity_counts.get("MEDIUM", 0) > 0:
        overall_risk = "CAUTION"
    else:
        overall_risk = "SAFE"

    report = {
        "scan_metadata": {
            "target": str(target),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": "dependency-auditor",
            "files_checked": len(files_checked),
        },
        "summary": {
            "overall_risk": overall_risk,
            "total_findings": len(all_findings),
            "by_severity": severity_counts,
            "dependency_files": files_checked,
        },
        "findings": all_findings,
    }

    return report


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: audit_deps.py <path-to-plugin-directory>"
        }, indent=2))
        sys.exit(0)

    target = sys.argv[1]
    if not os.path.isdir(target):
        print(json.dumps({"error": f"Not a directory: {target}"}), indent=2)
        sys.exit(1)

    report = audit_plugin(target)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

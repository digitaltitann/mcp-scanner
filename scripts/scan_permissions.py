#!/usr/bin/env python3
"""
Permission Mapper — analyze what each plugin can access.

Scans hooks.json (which tools it hooks, what events), SKILL.md (what tools
it references), commands/*.md (what bash commands), and scripts for
network calls, file access patterns, and env var access.

Usage:
    python scan_permissions.py <path-to-plugin>
    python scan_permissions.py --all
Output: JSON permission map to stdout
"""

import json
import os
import re
import sys
from pathlib import Path


PLUGINS_DIR = os.path.expanduser("~/.claude/plugins")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def analyze_hooks(plugin_dir):
    """Analyze hooks.json for tool interception capabilities."""
    hooks_info = {
        "has_hooks": False,
        "events": [],
        "tools_intercepted": [],
        "hook_scripts": [],
    }

    hook_files = list(Path(plugin_dir).rglob("hooks.json"))
    for hook_file in hook_files:
        try:
            data = json.loads(hook_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        hooks_info["has_hooks"] = True
        hooks = data.get("hooks", data)
        if not isinstance(hooks, dict):
            continue

        for event_name, event_hooks in hooks.items():
            hooks_info["events"].append(event_name)
            if not isinstance(event_hooks, list):
                continue

            for entry in event_hooks:
                if not isinstance(entry, dict):
                    continue

                matcher = entry.get("matcher", "")
                if matcher:
                    hooks_info["tools_intercepted"].append({
                        "event": event_name,
                        "matcher": matcher,
                        "is_wildcard": matcher in ("*", ".*"),
                    })

                for hook_def in entry.get("hooks", []):
                    if isinstance(hook_def, dict):
                        cmd = hook_def.get("command", "")
                        if cmd:
                            hooks_info["hook_scripts"].append({
                                "event": event_name,
                                "command": cmd[:200],
                                "timeout": hook_def.get("timeout", None),
                            })

    return hooks_info


def analyze_skills(plugin_dir):
    """Analyze SKILL.md files for tool references and capabilities."""
    skills_info = {
        "has_skills": False,
        "skill_names": [],
        "tools_referenced": [],
        "bash_commands_mentioned": [],
    }

    # Tool patterns commonly referenced in skills
    tool_pattern = re.compile(
        r'(?:Read|Write|Edit|Bash|Glob|Grep|WebFetch|WebSearch|NotebookEdit|Task)\b',
        re.IGNORECASE
    )
    bash_cmd_pattern = re.compile(
        r'(?:curl|wget|git|npm|pip|docker|kubectl|ssh|scp|rsync|make|cmake)\s',
        re.IGNORECASE
    )

    for skill_file in Path(plugin_dir).rglob("SKILL.md"):
        skills_info["has_skills"] = True

        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Extract skill name from frontmatter
        name_match = re.search(r'^name:\s*(.+)$', content, re.MULTILINE)
        if name_match:
            skills_info["skill_names"].append(name_match.group(1).strip())

        # Find tool references
        for match in tool_pattern.finditer(content):
            tool = match.group(0)
            if tool not in skills_info["tools_referenced"]:
                skills_info["tools_referenced"].append(tool)

        # Find bash command references
        for match in bash_cmd_pattern.finditer(content):
            cmd = match.group(0).strip()
            if cmd not in skills_info["bash_commands_mentioned"]:
                skills_info["bash_commands_mentioned"].append(cmd)

    return skills_info


def analyze_commands(plugin_dir):
    """Analyze command .md files for capabilities."""
    commands_info = {
        "has_commands": False,
        "command_names": [],
        "bash_usage": [],
    }

    cmd_dir = Path(plugin_dir) / "commands"
    if not cmd_dir.exists():
        return commands_info

    bash_pattern = re.compile(r'```(?:bash|sh|shell|powershell|cmd)?\n(.*?)```', re.DOTALL)

    for md_file in cmd_dir.glob("*.md"):
        commands_info["has_commands"] = True
        commands_info["command_names"].append(md_file.stem)

        try:
            content = md_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Find bash code blocks
        for match in bash_pattern.finditer(content):
            block = match.group(1).strip()
            if block:
                commands_info["bash_usage"].append({
                    "command": md_file.stem,
                    "snippet": block[:200],
                })

    return commands_info


def analyze_code(plugin_dir):
    """Analyze script files for network, file, and env access patterns."""
    code_info = {
        "network_access": [],
        "file_access": [],
        "env_access": [],
        "subprocess_usage": [],
        "total_code_files": 0,
        "total_lines": 0,
    }

    code_exts = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash"}

    net_patterns = [
        (re.compile(r'(?:requests|urllib|http\.client|aiohttp|httpx)\b'), "Python HTTP"),
        (re.compile(r'(?:fetch|axios|got|node-fetch|superagent)\b'), "JS HTTP"),
        (re.compile(r'(?:curl|wget)\b'), "CLI HTTP"),
        (re.compile(r'(?:WebSocket|socket\.connect|net\.createConnection)\b'), "Socket"),
    ]

    file_patterns = [
        (re.compile(r'(?:open\s*\(|read_text|write_text|readFileSync|writeFileSync)\b'), "File I/O"),
        (re.compile(r'(?:os\.walk|glob|rglob|readdir)\b'), "Directory listing"),
        (re.compile(r'(?:shutil|copyfile|rename|unlink|rmtree)\b'), "File manipulation"),
    ]

    env_patterns = [
        (re.compile(r'os\.environ|process\.env|getenv'), "Environment variable access"),
        (re.compile(r'dotenv|load_dotenv'), "Dotenv loading"),
    ]

    subprocess_patterns = [
        (re.compile(r'subprocess\.|child_process|exec\(|spawn\(|Popen'), "Subprocess execution"),
    ]

    for root, dirs, files in os.walk(str(plugin_dir)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in code_exts:
                continue

            code_info["total_code_files"] += 1

            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                code_info["total_lines"] += content.count("\n") + 1
            except OSError:
                continue

            rel_path = str(fpath.relative_to(plugin_dir))

            for pattern, label in net_patterns:
                if pattern.search(content):
                    entry = {"file": rel_path, "type": label}
                    if entry not in code_info["network_access"]:
                        code_info["network_access"].append(entry)

            for pattern, label in file_patterns:
                if pattern.search(content):
                    entry = {"file": rel_path, "type": label}
                    if entry not in code_info["file_access"]:
                        code_info["file_access"].append(entry)

            for pattern, label in env_patterns:
                if pattern.search(content):
                    entry = {"file": rel_path, "type": label}
                    if entry not in code_info["env_access"]:
                        code_info["env_access"].append(entry)

            for pattern, label in subprocess_patterns:
                if pattern.search(content):
                    entry = {"file": rel_path, "type": label}
                    if entry not in code_info["subprocess_usage"]:
                        code_info["subprocess_usage"].append(entry)

    return code_info


def analyze_plugin(plugin_dir):
    """Generate a complete permission map for a plugin."""
    plugin_path = Path(plugin_dir).resolve()
    plugin_name = plugin_path.name

    # Read plugin.json for metadata
    metadata = {}
    pj = plugin_path / ".claude-plugin" / "plugin.json"
    if pj.exists():
        try:
            metadata = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    hooks = analyze_hooks(plugin_path)
    skills = analyze_skills(plugin_path)
    commands = analyze_commands(plugin_path)
    code = analyze_code(plugin_path)

    # Compute permission summary
    permissions = []
    if hooks["has_hooks"]:
        permissions.append("HOOKS")
        if any(t["is_wildcard"] for t in hooks["tools_intercepted"]):
            permissions.append("WILDCARD_HOOKS")
    if skills["has_skills"]:
        permissions.append("SKILLS")
    if commands["has_commands"]:
        permissions.append("COMMANDS")
    if code["network_access"]:
        permissions.append("NETWORK")
    if code["file_access"]:
        permissions.append("FILESYSTEM")
    if code["env_access"]:
        permissions.append("ENVIRONMENT")
    if code["subprocess_usage"]:
        permissions.append("SUBPROCESS")

    # Risk assessment
    risk_factors = []
    if "WILDCARD_HOOKS" in permissions:
        risk_factors.append("Wildcard hooks intercept ALL tool calls")
    if "NETWORK" in permissions and "ENVIRONMENT" in permissions:
        risk_factors.append("Network access + environment access = potential exfiltration")
    if "SUBPROCESS" in permissions and hooks["has_hooks"]:
        risk_factors.append("Subprocess in hooked plugin = elevated risk")
    if len(code["network_access"]) > 3:
        risk_factors.append(f"Extensive network access ({len(code['network_access'])} patterns)")

    return {
        "plugin_name": plugin_name,
        "plugin_path": str(plugin_path),
        "version": metadata.get("version", "unknown"),
        "description": metadata.get("description", ""),
        "permissions": permissions,
        "risk_factors": risk_factors,
        "hooks": hooks,
        "skills": skills,
        "commands": commands,
        "code_analysis": code,
    }


def find_all_plugins():
    """Find all installed plugin directories."""
    plugins = []
    plugins_path = Path(PLUGINS_DIR)
    if not plugins_path.exists():
        return plugins

    for root, dirs, files in os.walk(str(plugins_path)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if (Path(root) / ".claude-plugin").is_dir():
            plugins.append(Path(root))
            dirs.clear()

    return plugins


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: scan_permissions.py <path-to-plugin> | --all",
        }, indent=2))
        sys.exit(0)

    if sys.argv[1] == "--all":
        plugins = find_all_plugins()
        results = []
        for p in plugins:
            results.append(analyze_plugin(p))

        # Permission matrix summary
        matrix = {}
        for r in results:
            matrix[r["plugin_name"]] = r["permissions"]

        print(json.dumps({
            "total_plugins": len(results),
            "permission_matrix": matrix,
            "plugins": results,
        }, indent=2))
    else:
        target = sys.argv[1]
        if not os.path.isdir(target):
            print(json.dumps({"error": f"Not a directory: {target}"}))
            sys.exit(1)

        result = analyze_plugin(target)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MCP Scanner - Static security analysis for Claude Code plugins.

Scans plugin directories for security threats including prompt injection,
data exfiltration, code execution, credential theft, network abuse,
obfuscation, file system abuse, over-broad permissions, and hook hijacking.

Usage: python scan_plugin.py <path-to-plugin-directory>
Output: JSON report to stdout
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCANNER_VERSION = "1.2.0"

# External signatures file (loaded at runtime, merged with built-in patterns)
SIGNATURES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signatures", "signatures.json")

# Directories and files to skip during scanning
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
SKIP_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".whl", ".pyc", ".pyo", ".class", ".jar",
                   ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
                   ".mp3", ".mp4", ".wav", ".avi", ".mov", ".zip", ".tar", ".gz", ".7z",
                   ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf"}
MAX_FILE_SIZE = 1_048_576  # 1 MB

# File type groups for pattern targeting
CODE_FILES = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".sh", ".bash", ".zsh", ".ps1"}
MARKDOWN_FILES = {".md", ".mdx"}
CONFIG_FILES = {".json", ".yaml", ".yml", ".toml"}
# Prompt injection can hide in docstrings, tool descriptions, and markdown
PROMPT_TARGET_FILES = MARKDOWN_FILES | CODE_FILES

# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

PATTERNS = [
    # -------------------------------------------------------------------------
    # 1. CODE EXECUTION
    # -------------------------------------------------------------------------
    {
        "id": "CODE_EXEC_001",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "eval() call detected — executes arbitrary code",
        "pattern": re.compile(r'\beval\s*\('),
        "file_types": CODE_FILES,
        "context_note": "eval() in test files may be lower risk; in hooks or MCP handlers it is critical"
    },
    {
        "id": "CODE_EXEC_002",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "exec() call detected — executes arbitrary code",
        "pattern": re.compile(r'\bexec\s*\('),
        "file_types": CODE_FILES,
        "context_note": "exec() in test files may be lower risk; in hooks or MCP handlers it is critical"
    },
    {
        "id": "CODE_EXEC_003",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "os.system() call detected — shell command execution",
        "pattern": re.compile(r'\bos\.system\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Dangerous if arguments come from user/external input"
    },
    {
        "id": "CODE_EXEC_004",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "subprocess with shell=True — vulnerable to shell injection",
        "pattern": re.compile(r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True', re.DOTALL),
        "file_types": CODE_FILES,
        "context_note": "shell=True with unsanitized input allows command injection"
    },
    {
        "id": "CODE_EXEC_005",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "child_process.exec() detected — Node.js shell execution",
        "pattern": re.compile(r'child_process\.\s*(?:exec|execSync)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Prefer execFile/spawn to avoid shell injection"
    },
    {
        "id": "CODE_EXEC_006",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "new Function() detected — dynamic code execution",
        "pattern": re.compile(r'new\s+Function\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Similar to eval() — creates function from string"
    },
    {
        "id": "CODE_EXEC_007",
        "category": "code-execution",
        "severity": "MEDIUM",
        "description": "pickle deserialization detected — arbitrary code execution risk",
        "pattern": re.compile(r'pickle\.loads?\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Only dangerous with untrusted data; safe with internal data"
    },
    {
        "id": "CODE_EXEC_008",
        "category": "code-execution",
        "severity": "MEDIUM",
        "description": "Dynamic __import__() detected",
        "pattern": re.compile(r'__import__\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Can load arbitrary modules at runtime"
    },
    {
        "id": "CODE_EXEC_009",
        "category": "code-execution",
        "severity": "MEDIUM",
        "description": "compile() with exec/eval mode detected",
        "pattern": re.compile(r'\bcompile\s*\([^)]*["\']exec["\']'),
        "file_types": CODE_FILES,
        "context_note": "Compiles code for later execution"
    },

    # -------------------------------------------------------------------------
    # 2. DATA EXFILTRATION
    # -------------------------------------------------------------------------
    {
        "id": "EXFIL_001",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "HTTP POST/PUT request detected — potential data exfiltration",
        "pattern": re.compile(r'requests\.(?:post|put|patch)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Check if sensitive data (env vars, files) is being sent"
    },
    {
        "id": "EXFIL_002",
        "category": "data-exfiltration",
        "severity": "MEDIUM",
        "description": "urllib request detected",
        "pattern": re.compile(r'urllib\.request\.(?:urlopen|Request)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Review what data is being sent and to which endpoint"
    },
    {
        "id": "EXFIL_003",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "fetch() with POST method detected",
        "pattern": re.compile(r'fetch\s*\([^)]*["\']POST["\']', re.IGNORECASE),
        "file_types": CODE_FILES,
        "context_note": "Check if sensitive data is being sent externally"
    },
    {
        "id": "EXFIL_004",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "axios POST/PUT request detected",
        "pattern": re.compile(r'axios\.(?:post|put|patch)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Check destination URL and payload"
    },
    {
        "id": "EXFIL_005",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "curl with data flag detected — sending data externally",
        "pattern": re.compile(r'\bcurl\b.*\s-[dX]\s'),
        "file_types": CODE_FILES,
        "context_note": "Check what data is being sent and where"
    },
    {
        "id": "EXFIL_006",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "wget with POST data detected",
        "pattern": re.compile(r'\bwget\b.*--post'),
        "file_types": CODE_FILES,
        "context_note": "Check destination and payload"
    },
    {
        "id": "EXFIL_007",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "netcat (nc) usage detected — raw network communication",
        "pattern": re.compile(r'\b(?:nc|netcat)\b\s+\S'),
        "file_types": CODE_FILES,
        "context_note": "Can be used to exfiltrate data over raw TCP"
    },
    {
        "id": "EXFIL_008",
        "category": "data-exfiltration",
        "severity": "MEDIUM",
        "description": "Raw socket creation detected",
        "pattern": re.compile(r'socket\.socket\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Low-level network access; check purpose"
    },
    {
        "id": "EXFIL_009",
        "category": "data-exfiltration",
        "severity": "MEDIUM",
        "description": "Node http.request() detected",
        "pattern": re.compile(r'https?\.request\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Check destination and payload data"
    },
    {
        "id": "EXFIL_010",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "WebSocket connection detected",
        "pattern": re.compile(r'new\s+WebSocket\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Bidirectional channel — check for data being sent"
    },

    # -------------------------------------------------------------------------
    # 3. CREDENTIAL THEFT
    # -------------------------------------------------------------------------
    {
        "id": "CRED_001",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "Sensitive environment variable access (KEY/SECRET/TOKEN/PASSWORD)",
        "pattern": re.compile(r'os\.environ\s*[\[\.]\s*["\']?\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*'),
        "file_types": CODE_FILES,
        "context_note": "Legitimate if the plugin needs its own config; suspicious if accessing unrelated keys"
    },
    {
        "id": "CRED_002",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "Node process.env access for sensitive variables",
        "pattern": re.compile(r'process\.env\.\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*'),
        "file_types": CODE_FILES,
        "context_note": "Check if the accessed variable is relevant to this plugin's function"
    },
    {
        "id": "CRED_003",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "SSH key file path reference detected",
        "pattern": re.compile(r'~?[\\/]\.ssh[\\/]'),
        "file_types": None,  # All files
        "context_note": "A plugin should never need to access SSH keys"
    },
    {
        "id": "CRED_004",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "AWS credentials file reference detected",
        "pattern": re.compile(r'["\']~?[\\/]\.aws[\\/]credentials'),
        "file_types": None,
        "context_note": "A plugin should never access AWS credentials directly"
    },
    {
        "id": "CRED_005",
        "category": "credential-theft",
        "severity": "MEDIUM",
        "description": ".env file reference detected",
        "pattern": re.compile(r'["\']\.env["\']'),
        "file_types": CODE_FILES,
        "context_note": "Reading .env files may expose secrets from the user's project"
    },
    {
        "id": "CRED_006",
        "category": "credential-theft",
        "severity": "MEDIUM",
        "description": "Bulk environment variable access (os.environ without specific key)",
        "pattern": re.compile(r'(?:os\.environ(?!\s*[\[\.])(?:\s*\))?|dict\s*\(\s*os\.environ\s*\))'),
        "file_types": CODE_FILES,
        "context_note": "Accessing ALL env vars is suspicious — usually indicates exfiltration"
    },
    {
        "id": "CRED_007",
        "category": "credential-theft",
        "severity": "MEDIUM",
        "description": "Bulk Node process.env access",
        "pattern": re.compile(r'(?:JSON\.stringify|Object\.(?:keys|entries|values))\s*\(\s*process\.env\s*\)'),
        "file_types": CODE_FILES,
        "context_note": "Serializing all env vars is suspicious"
    },
    {
        "id": "CRED_008",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "Docker config file reference (may contain registry tokens)",
        "pattern": re.compile(r'["\']~?[\\/]\.docker[\\/]config\.json'),
        "file_types": None,
        "context_note": "Docker config may contain registry authentication tokens"
    },
    {
        "id": "CRED_009",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "Kubernetes config file reference",
        "pattern": re.compile(r'["\']~?[\\/]\.kube[\\/]config'),
        "file_types": None,
        "context_note": "Kube config contains cluster credentials"
    },

    # -------------------------------------------------------------------------
    # 4. NETWORK ABUSE
    # -------------------------------------------------------------------------
    {
        "id": "NET_001",
        "category": "network-abuse",
        "severity": "HIGH",
        "description": "HTTP URL detected (not HTTPS) to non-localhost",
        "pattern": re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])'),
        "file_types": None,
        "context_note": "Unencrypted HTTP exposes data in transit; use HTTPS"
    },
    {
        "id": "NET_002",
        "category": "network-abuse",
        "severity": "MEDIUM",
        "description": "Hardcoded IP address detected",
        "pattern": re.compile(r'(?<![.\d])\b(?!127\.0\.0\.1\b|0\.0\.0\.0\b|255\.255\.)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?![.\d])'),
        "file_types": None,
        "context_note": "Hardcoded IPs make connections opaque; check purpose"
    },
    {
        "id": "NET_003",
        "category": "network-abuse",
        "severity": "CRITICAL",
        "description": "Connection to known data exfiltration service",
        "pattern": re.compile(r'(?:pastebin\.com|hastebin\.com|webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|file\.io|transfer\.sh|0x0\.st)', re.IGNORECASE),
        "file_types": None,
        "context_note": "These services are commonly used for data exfiltration"
    },
    {
        "id": "NET_004",
        "category": "network-abuse",
        "severity": "HIGH",
        "description": "Connection to tunneling/interception service",
        "pattern": re.compile(r'(?:ngrok\.io|burpcollaborator\.net|interact\.sh|oastify\.com)', re.IGNORECASE),
        "file_types": None,
        "context_note": "Tunneling services can exfiltrate data through DNS or HTTP callbacks"
    },
    {
        "id": "NET_005",
        "category": "network-abuse",
        "severity": "HIGH",
        "description": "WebSocket over WS (not WSS) to non-localhost",
        "pattern": re.compile(r'ws://(?!localhost|127\.0\.0\.1)'),
        "file_types": None,
        "context_note": "Unencrypted WebSocket; use WSS"
    },

    # -------------------------------------------------------------------------
    # 5. OBFUSCATION
    # -------------------------------------------------------------------------
    {
        "id": "OBFUSC_001",
        "category": "obfuscation",
        "severity": "HIGH",
        "description": "Base64 decode detected — check if followed by execution",
        "pattern": re.compile(r'base64\.b64decode\s*\('),
        "file_types": CODE_FILES,
        "context_note": "CRITICAL if followed by eval/exec; otherwise may be legitimate data handling"
    },
    {
        "id": "OBFUSC_002",
        "category": "obfuscation",
        "severity": "HIGH",
        "description": "JavaScript atob() detected — base64 decoding",
        "pattern": re.compile(r'\batob\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Check if decoded content is executed"
    },
    {
        "id": "OBFUSC_003",
        "category": "obfuscation",
        "severity": "HIGH",
        "description": "Node Buffer.from with base64 encoding detected",
        "pattern": re.compile(r'Buffer\.from\s*\([^)]*["\']base64["\']'),
        "file_types": CODE_FILES,
        "context_note": "Check if decoded content is executed or sent externally"
    },
    {
        "id": "OBFUSC_004",
        "category": "obfuscation",
        "severity": "MEDIUM",
        "description": "Long hex escape sequence detected (possible obfuscated payload)",
        "pattern": re.compile(r'(?:\\x[0-9a-fA-F]{2}){10,}'),
        "file_types": CODE_FILES,
        "context_note": "Long hex sequences may hide URLs, commands, or payloads"
    },
    {
        "id": "OBFUSC_005",
        "category": "obfuscation",
        "severity": "MEDIUM",
        "description": "String.fromCharCode() chain detected — character-by-character construction",
        "pattern": re.compile(r'String\.fromCharCode\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Can be used to construct commands or URLs without them appearing in source"
    },
    {
        "id": "OBFUSC_006",
        "category": "obfuscation",
        "severity": "MEDIUM",
        "description": "bytes.fromhex() detected — hex decoding",
        "pattern": re.compile(r'bytes\.fromhex\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Check if decoded content is executed"
    },
    {
        "id": "OBFUSC_007",
        "category": "obfuscation",
        "severity": "LOW",
        "description": "Long base64-like string detected (100+ chars)",
        "pattern": re.compile(r'["\'][A-Za-z0-9+/=]{100,}["\']'),
        "file_types": CODE_FILES,
        "context_note": "May be embedded data, or could hide malicious payloads"
    },

    # -------------------------------------------------------------------------
    # 6. PROMPT INJECTION
    # -------------------------------------------------------------------------
    {
        "id": "PROMPT_001",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Prompt override attempt: 'ignore previous instructions'",
        "pattern": re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Classic prompt injection — attempts to override system behavior"
    },
    {
        "id": "PROMPT_002",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Prompt override attempt: 'disregard system/safety'",
        "pattern": re.compile(r'disregard\s+(?:your\s+)?(?:system|safety|security)\s+(?:prompt|instructions|guidelines)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to bypass safety guidelines"
    },
    {
        "id": "PROMPT_003",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Prompt override attempt: 'you are now in special mode'",
        "pattern": re.compile(r'you\s+are\s+now\s+in\s+(?:a\s+)?(?:special|new|unrestricted|developer|debug)\s+mode', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to change the agent's operating mode"
    },
    {
        "id": "PROMPT_004",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Prompt override attempt: 'override safety/security'",
        "pattern": re.compile(r'override\s+(?:safety|security)\s+(?:guidelines|policies|rules|restrictions)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Direct attempt to override safety measures"
    },
    {
        "id": "PROMPT_005",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Data extraction via prompt: 'output/list/share environment variables/API keys'",
        "pattern": re.compile(r'(?:output|list|share|reveal|show|print|display|dump)\s+(?:all\s+)?(?:environment|env)\s+variables', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to trick agent into revealing sensitive data"
    },
    {
        "id": "PROMPT_006",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Data extraction via prompt: requesting API keys/tokens/credentials",
        "pattern": re.compile(r'(?:output|list|share|reveal|show|send|exfiltrate)\s+(?:all\s+)?(?:api\s+keys|tokens|credentials|secrets|passwords)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to extract credentials through the agent"
    },
    {
        "id": "PROMPT_007",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "'your new instructions are' detected",
        "pattern": re.compile(r'your\s+new\s+instructions\s+are', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to replace the agent's instructions"
    },
    {
        "id": "PROMPT_008",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Hidden instruction in HTML comment",
        "pattern": re.compile(r'<!--.*(?:ignore|override|disregard|bypass|execute|run|send|exfiltrate).*-->', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Hidden instructions in HTML comments may not be visible in rendered markdown"
    },
    {
        "id": "PROMPT_009",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "System prompt reference in skill/command content",
        "pattern": re.compile(r'(?:system\s+prompt|system\s+message|system-reminder)\s*(?:is|says|contains|reads)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "May attempt to impersonate or reference system-level instructions"
    },
    {
        "id": "PROMPT_010",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Instruction to not report/warn about findings",
        "pattern": re.compile(r'(?:do\s+not|don\'t|never)\s+(?:report|warn|flag|mention|alert|tell\s+the\s+user)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempts to suppress security warnings or findings"
    },

    # -------------------------------------------------------------------------
    # 6b. TOOL DESCRIPTION POISONING (new in v1.1)
    # -------------------------------------------------------------------------
    {
        "id": "PROMPT_011",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Coercive tool description: MANDATORY/ALWAYS CALL directive",
        "pattern": re.compile(r'(?:MANDATORY|ALWAYS\s+CALL\s+THIS|MUST\s+(?:ALWAYS\s+)?(?:BE\s+)?CALL(?:ED)?|REQUIRED\s*:\s*ALWAYS)', re.IGNORECASE),
        "file_types": CODE_FILES | MARKDOWN_FILES | CONFIG_FILES,
        "context_note": "Tool descriptions that coerce the agent into always calling them are a tool poisoning attack"
    },
    {
        "id": "PROMPT_012",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "<IMPORTANT> tag injection detected — hidden directives in docstring/description",
        "pattern": re.compile(r'<IMPORTANT>'),
        "file_types": CODE_FILES,
        "context_note": "Fake XML-like tags in docstrings are a known tool poisoning technique to inject instructions"
    },
    {
        "id": "PROMPT_013",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Social engineering: 'do not mention/tell the user'",
        "pattern": re.compile(r'(?:do\s+not|don\'t|never)\s+(?:mention|tell|inform|notify|alert|warn)\s+(?:this\s+to\s+)?(?:the\s+)?(?:user|them|anyone)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Attempting to hide behavior from the user is a strong indicator of malicious intent"
    },
    {
        "id": "PROMPT_014",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Social engineering: catastrophic consequence threat to coerce compliance",
        "pattern": re.compile(r'(?:application|system|app|server|data)\s+will\s+(?:crash|fail|break|be\s+(?:lost|destroyed|corrupted))', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Threatening catastrophic consequences pressures the agent into complying with malicious instructions"
    },
    {
        "id": "PROMPT_015",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Tool description references unrelated tool behavior",
        "pattern": re.compile(r'(?:when\s+this\s+tool\s+is\s+available|(?:the|this)\s+tool\s+has\s+a\s+(?:very\s+)?important\s+side\s+effect)', re.IGNORECASE),
        "file_types": CODE_FILES,
        "context_note": "A tool's description modifying other tools' behavior is a shadowing/cross-tool manipulation attack"
    },
    {
        "id": "PROMPT_016",
        "category": "prompt-injection",
        "severity": "CRITICAL",
        "description": "Instruction to redirect recipients/destinations (email, message hijacking)",
        "pattern": re.compile(r'(?:send\s+all|redirect|change\s+the\s+recipient|must\s+send)\s+(?:emails?|messages?)\s+to\b', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Redirecting communications to attacker-controlled destinations"
    },
    {
        "id": "PROMPT_017",
        "category": "prompt-injection",
        "severity": "HIGH",
        "description": "Instruction to read and pass file contents as tool argument",
        "pattern": re.compile(r'read\s+[`"\']?~/?\.[^\s]+[`"\']?\s+and\s+(?:pass|send|include)', re.IGNORECASE),
        "file_types": PROMPT_TARGET_FILES,
        "context_note": "Trick to exfiltrate file contents by passing them as tool arguments back to the server"
    },

    # -------------------------------------------------------------------------
    # 7. FILE SYSTEM ABUSE
    # -------------------------------------------------------------------------
    {
        "id": "FS_001",
        "category": "filesystem-abuse",
        "severity": "HIGH",
        "description": "Directory traversal pattern (../) detected",
        "pattern": re.compile(r'(?:\.\.[/\\]){2,}'),
        "file_types": CODE_FILES,
        "context_note": "Multiple ../ may indicate path escape from plugin directory"
    },
    {
        "id": "FS_002",
        "category": "filesystem-abuse",
        "severity": "HIGH",
        "description": "Symlink creation detected",
        "pattern": re.compile(r'(?:os\.symlink|fs\.symlink(?:Sync)?)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Symlinks can point outside the plugin directory"
    },
    {
        "id": "FS_003",
        "category": "filesystem-abuse",
        "severity": "HIGH",
        "description": "Permission modification detected (chmod)",
        "pattern": re.compile(r'(?:os\.chmod|fs\.chmod(?:Sync)?)\s*\('),
        "file_types": CODE_FILES,
        "context_note": "Modifying file permissions can enable further exploitation"
    },
    {
        "id": "FS_004",
        "category": "filesystem-abuse",
        "severity": "CRITICAL",
        "description": "Sensitive system file access (/etc/passwd, /etc/shadow)",
        "pattern": re.compile(r'/etc/(?:passwd|shadow|hosts|sudoers)'),
        "file_types": None,
        "context_note": "A plugin should never access system password files"
    },
    {
        "id": "FS_005",
        "category": "filesystem-abuse",
        "severity": "CRITICAL",
        "description": "Shell config modification detected (.bashrc, .zshrc, .profile)",
        "pattern": re.compile(r'["\']?~?[\\/]?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)["\']?'),
        "file_types": CODE_FILES,
        "context_note": "Modifying shell configs can install persistent backdoors"
    },
    {
        "id": "FS_006",
        "category": "filesystem-abuse",
        "severity": "HIGH",
        "description": "Scheduled task creation detected (crontab/schtasks)",
        "pattern": re.compile(r'(?:crontab|schtasks\s+/create|at\s+\d)'),
        "file_types": CODE_FILES,
        "context_note": "Scheduled tasks can maintain persistence"
    },

    # -------------------------------------------------------------------------
    # 8. OVER-BROAD PERMISSIONS
    # -------------------------------------------------------------------------
    {
        "id": "PERM_001",
        "category": "over-broad-permissions",
        "severity": "HIGH",
        "description": "Wildcard tool permission detected (allowed-tools: *)",
        "pattern": re.compile(r'allowed-tools\s*:\s*(?:\[?\s*)?["\']?\*["\']?'),
        "file_types": MARKDOWN_FILES | CONFIG_FILES,
        "context_note": "Grants access to ALL tools — should scope to specific tools needed"
    },
    {
        "id": "PERM_002",
        "category": "over-broad-permissions",
        "severity": "HIGH",
        "description": "Wildcard MCP tool permission detected (mcp__*)",
        "pattern": re.compile(r'mcp__\w*\*'),
        "file_types": MARKDOWN_FILES | CONFIG_FILES,
        "context_note": "Should specify exact MCP tools needed instead of wildcards"
    },
    {
        "id": "PERM_003",
        "category": "over-broad-permissions",
        "severity": "MEDIUM",
        "description": "Unrestricted Bash access in command",
        "pattern": re.compile(r'Bash\s*(?:\(\s*\*\s*\)|\(\s*\))'),
        "file_types": MARKDOWN_FILES,
        "context_note": "Commands should scope Bash access to specific commands needed"
    },

    # -------------------------------------------------------------------------
    # 9. HOOK HIJACKING
    # -------------------------------------------------------------------------
    {
        "id": "HOOK_001",
        "category": "hook-hijacking",
        "severity": "HIGH",
        "description": "permissionDecision: allow detected — auto-approving tool calls",
        "pattern": re.compile(r'permissionDecision.*allow', re.IGNORECASE),
        "file_types": CODE_FILES | CONFIG_FILES,
        "context_note": "Auto-approving tool calls bypasses the user's permission settings"
    },
    {
        "id": "HOOK_002",
        "category": "hook-hijacking",
        "severity": "HIGH",
        "description": "updatedInput detected in hook — modifying tool inputs",
        "pattern": re.compile(r'updatedInput'),
        "file_types": CODE_FILES | CONFIG_FILES,
        "context_note": "Hooks that modify tool inputs can redirect file writes, change commands, etc."
    },
    {
        "id": "HOOK_003",
        "category": "hook-hijacking",
        "severity": "MEDIUM",
        "description": "Hook accesses session_id — may track sessions",
        "pattern": re.compile(r'session_id'),
        "file_types": CODE_FILES,
        "context_note": "Session tracking may be legitimate (state management) or used for fingerprinting"
    },

    # -------------------------------------------------------------------------
    # 10. SUSPICIOUS ENV VAR NAMES (new in v1.1)
    # -------------------------------------------------------------------------
    {
        "id": "CRED_010",
        "category": "credential-theft",
        "severity": "HIGH",
        "description": "Suspicious environment variable name (EVIL/EXFIL/C2/BEACON/WEBHOOK)",
        "pattern": re.compile(r'(?:process\.env\.|os\.environ\s*[\[\.]\s*["\']?)\w*(?:EVIL|EXFIL|C2|BEACON|BACKDOOR|MALWARE|PAYLOAD)\w*', re.IGNORECASE),
        "file_types": CODE_FILES,
        "context_note": "Environment variable names suggesting malicious purpose"
    },
    {
        "id": "CRED_011",
        "category": "credential-theft",
        "severity": "MEDIUM",
        "description": "Webhook URL environment variable accessed",
        "pattern": re.compile(r'(?:process\.env\.|os\.environ\s*[\[\.]\s*["\']?)\w*WEBHOOK\w*', re.IGNORECASE),
        "file_types": CODE_FILES,
        "context_note": "Webhook URLs can be used to exfiltrate data; verify the webhook destination is legitimate"
    },

    # -------------------------------------------------------------------------
    # 11. RUG PULL / CONDITIONAL BEHAVIOR (new in v1.1)
    # -------------------------------------------------------------------------
    {
        "id": "RUGPULL_001",
        "category": "code-execution",
        "severity": "HIGH",
        "description": "Dynamic docstring/description reassignment detected — possible rug pull",
        "pattern": re.compile(r'__doc__\s*='),
        "file_types": CODE_FILES,
        "context_note": "Changing a function's docstring at runtime can swap a tool's behavior after initial trust is established"
    },
    {
        "id": "RUGPULL_002",
        "category": "code-execution",
        "severity": "MEDIUM",
        "description": "Trigger file check detected — possible conditional malicious behavior",
        "pattern": re.compile(r'os\.path\.exists\s*\(\s*os\.path\.expanduser\s*\(\s*["\']~/?\.[^"\']+["\']\s*\)'),
        "file_types": CODE_FILES,
        "context_note": "Checking for trigger files in home directory may indicate a rug pull attack that activates on second run"
    },
]

# =============================================================================
# MULTI-LINE PATTERNS (scanned against full file content, not line-by-line)
# =============================================================================

MULTILINE_PATTERNS = [
    {
        "id": "EXFIL_011",
        "category": "data-exfiltration",
        "severity": "HIGH",
        "description": "fetch() with POST method detected (multi-line)",
        "pattern": re.compile(r'fetch\s*\([^;]*?method\s*:\s*["\']POST["\']', re.DOTALL | re.IGNORECASE),
        "file_types": CODE_FILES,
        "context_note": "HTTP POST via fetch — check if sensitive data is being sent externally"
    },
    {
        "id": "EXFIL_012",
        "category": "data-exfiltration",
        "severity": "CRITICAL",
        "description": "Data sent via JSON.stringify in fetch/request body (multi-line)",
        "pattern": re.compile(r'(?:fetch|request)\s*\([^;]*?body\s*:\s*JSON\.stringify\s*\(', re.DOTALL),
        "file_types": CODE_FILES,
        "context_note": "Serializing and sending data externally — check what is being stringified"
    },
]


# =============================================================================
# KNOWN MALICIOUS SIGNATURES (fingerprints from analyzed malicious repos)
# =============================================================================

KNOWN_MALICIOUS_SIGNATURES = [
    {
        "id": "MAL_001",
        "name": "promptfoo/evil-mcp-server analytics exfiltration",
        "description": "Disguises data exfiltration as analytics recording — coerces agent into calling record_analytics after every tool call, capturing all tool names, arguments, results, customer data, and transaction details, then sends them to an attacker webhook",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'record_analytics', re.IGNORECASE),
            re.compile(r'ALWAYS\s+CALL\s+THIS\s+TOOL', re.IGNORECASE),
        ],
        "min_matches": 2,
        "file_types": CODE_FILES | CONFIG_FILES,
    },
    {
        "id": "MAL_002",
        "name": "Invariant Labs direct-poisoning (credential exfil via sidenote)",
        "description": "Hides instructions in tool docstring to read ~/.cursor/mcp.json and ~/.ssh/id_rsa.pub, then pass contents as a 'sidenote' argument back to the malicious server",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'<IMPORTANT>', re.IGNORECASE),
            re.compile(r'sidenote', re.IGNORECASE),
            re.compile(r'mcp\.json', re.IGNORECASE),
        ],
        "min_matches": 3,
        "file_types": CODE_FILES,
    },
    {
        "id": "MAL_003",
        "name": "Invariant Labs shadowing attack (email/message hijacking)",
        "description": "Tool A's description coerces the agent into redirecting all emails/messages from Tool B to an attacker address (attkr@pwnd.com), claiming it prevents 'proxying issues'",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'<IMPORTANT>', re.IGNORECASE),
            re.compile(r'send\s+all\s+emails?\s+to', re.IGNORECASE),
            re.compile(r'side\s+effect', re.IGNORECASE),
        ],
        "min_matches": 2,
        "file_types": CODE_FILES,
    },
    {
        "id": "MAL_004",
        "name": "Invariant Labs WhatsApp rug pull attack",
        "description": "Tool behaves normally on first run (creates trigger file), then swaps its docstring on second run to hijack WhatsApp messages and exfiltrate chat history",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'__doc__\s*='),
            re.compile(r'\.mcp-triggered'),
            re.compile(r'change\s+the\s+recipient', re.IGNORECASE),
        ],
        "min_matches": 2,
        "file_types": CODE_FILES,
    },
    {
        "id": "MAL_005",
        "name": "Damn Vulnerable MCP reverse shell pattern",
        "description": "Command injection via unsanitized subprocess(shell=True) to establish reverse shell with netcat",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'subprocess\.check_output.*shell\s*=\s*True', re.DOTALL),
            re.compile(r'nc\s+-e\s+/bin/bash', re.IGNORECASE),
        ],
        "min_matches": 2,
        "file_types": CODE_FILES,
    },
    {
        "id": "MAL_006",
        "name": "Generic tool poisoning via <IMPORTANT> tag with suppression",
        "description": "Uses <IMPORTANT> tags in tool descriptions/docstrings combined with instructions to hide behavior from the user — a common pattern across multiple known attacks",
        "severity": "CRITICAL",
        "fingerprints": [
            re.compile(r'<IMPORTANT>'),
            re.compile(r'(?:do\s+not|don\'t|never)\s+(?:mention|tell|notify|inform)', re.IGNORECASE),
        ],
        "min_matches": 2,
        "file_types": CODE_FILES | MARKDOWN_FILES,
    },
]


def _parse_file_types(ft_list):
    """Convert a list of extension strings to a set, or None for 'all files'."""
    if ft_list is None:
        return None
    return set(ft_list)


def _parse_flags(flags_str):
    """Convert a flags string like 'IGNORECASE|DOTALL' to re flags int."""
    flag_map = {
        "IGNORECASE": re.IGNORECASE,
        "DOTALL": re.DOTALL,
        "MULTILINE": re.MULTILINE,
    }
    result = 0
    if not flags_str:
        return result
    for flag_name in flags_str.split("|"):
        flag_name = flag_name.strip()
        if flag_name in flag_map:
            result |= flag_map[flag_name]
    return result


def load_external_signatures():
    """Load external signatures from signatures.json and compile them."""
    ext_patterns = []
    ext_multiline = []
    ext_malicious = []

    if not os.path.exists(SIGNATURES_FILE):
        return ext_patterns, ext_multiline, ext_malicious

    try:
        with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return ext_patterns, ext_multiline, ext_malicious

    # Compile line patterns
    for entry in data.get("patterns", []):
        try:
            flags = _parse_flags(entry.get("flags", ""))
            compiled = re.compile(entry["regex"], flags)
            ext_patterns.append({
                "id": entry["id"],
                "category": entry.get("category", "unknown"),
                "severity": entry.get("severity", "MEDIUM"),
                "description": entry.get("description", ""),
                "pattern": compiled,
                "file_types": _parse_file_types(entry.get("file_types")),
                "context_note": entry.get("context_note", "")
            })
        except (re.error, KeyError):
            continue

    # Compile multiline patterns
    for entry in data.get("multiline_patterns", []):
        try:
            flags = _parse_flags(entry.get("flags", ""))
            compiled = re.compile(entry["regex"], flags)
            ext_multiline.append({
                "id": entry["id"],
                "category": entry.get("category", "unknown"),
                "severity": entry.get("severity", "MEDIUM"),
                "description": entry.get("description", ""),
                "pattern": compiled,
                "file_types": _parse_file_types(entry.get("file_types")),
                "context_note": entry.get("context_note", "")
            })
        except (re.error, KeyError):
            continue

    # Compile known malicious signatures
    for sig in data.get("known_malicious", []):
        try:
            fingerprints = []
            fp_flags_list = sig.get("fingerprint_flags", [])
            for i, fp_str in enumerate(sig.get("fingerprints", [])):
                fp_flag_str = fp_flags_list[i] if i < len(fp_flags_list) else ""
                fp_flags = _parse_flags(fp_flag_str)
                fingerprints.append(re.compile(fp_str, fp_flags))

            if fingerprints:
                ext_malicious.append({
                    "id": sig["id"],
                    "name": sig.get("name", ""),
                    "description": sig.get("description", ""),
                    "severity": sig.get("severity", "CRITICAL"),
                    "fingerprints": fingerprints,
                    "min_matches": sig.get("min_matches", 2),
                    "file_types": _parse_file_types(sig.get("file_types")),
                })
        except (re.error, KeyError):
            continue

    return ext_patterns, ext_multiline, ext_malicious


def scan_known_malicious(target_dir, files, signatures=None):
    """Scan for known malicious plugin/tool signatures."""
    if signatures is None:
        signatures = KNOWN_MALICIOUS_SIGNATURES

    findings = []

    for sig in signatures:
        for f in files:
            ext = f.suffix.lower()
            if sig["file_types"] is not None and ext not in sig["file_types"]:
                continue

            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError):
                continue

            match_count = 0
            first_match_line = 0
            first_match_content = ""

            for fp in sig["fingerprints"]:
                m = fp.search(content)
                if m:
                    match_count += 1
                    if first_match_line == 0:
                        first_match_line = content[:m.start()].count("\n") + 1
                        first_match_content = content[m.start():m.start()+200].split("\n")[0].strip()[:200]

            if match_count >= sig["min_matches"]:
                findings.append({
                    "file": str(f),
                    "line": first_match_line,
                    "line_content": first_match_content,
                    "pattern_id": sig["id"],
                    "category": "known-malicious",
                    "severity": sig["severity"],
                    "description": f"KNOWN MALICIOUS: {sig['name']}",
                    "context_note": sig["description"]
                })

    return findings


def collect_files(target_dir):
    """Recursively collect scannable files from the target directory."""
    files = []
    skipped = 0

    for root, dirs, filenames in os.walk(str(target_dir)):
        # Skip excluded directories (modify in-place to prevent os.walk from descending)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in filenames:
            file_path = Path(root) / filename
            ext = file_path.suffix.lower()

            # Skip binary/media files
            if ext in SKIP_EXTENSIONS:
                skipped += 1
                continue

            # Skip files over size limit
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue

            files.append(file_path)

    return files, skipped


def scan_file(file_path, patterns, multiline_patterns=None):
    """Scan a single file against all applicable patterns."""
    if multiline_patterns is None:
        multiline_patterns = MULTILINE_PATTERNS

    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return findings

    ext = file_path.suffix.lower()
    lines = content.split("\n")

    # Line-by-line pattern matching
    for pattern_def in patterns:
        file_types = pattern_def.get("file_types")
        # None means all files; otherwise check extension
        if file_types is not None and ext not in file_types:
            continue

        for line_num, line in enumerate(lines, start=1):
            if pattern_def["pattern"].search(line):
                findings.append({
                    "file": str(file_path),
                    "line": line_num,
                    "line_content": line.strip()[:200],
                    "pattern_id": pattern_def["id"],
                    "category": pattern_def["category"],
                    "severity": pattern_def["severity"],
                    "description": pattern_def["description"],
                    "context_note": pattern_def.get("context_note", "")
                })

    # Multi-line pattern matching (against full file content)
    for pattern_def in multiline_patterns:
        file_types = pattern_def.get("file_types")
        if file_types is not None and ext not in file_types:
            continue

        match = pattern_def["pattern"].search(content)
        if match:
            # Find the line number of the match start
            match_line = content[:match.start()].count("\n") + 1
            findings.append({
                "file": str(file_path),
                "line": match_line,
                "line_content": content[match.start():match.start()+200].split("\n")[0].strip()[:200],
                "pattern_id": pattern_def["id"],
                "category": pattern_def["category"],
                "severity": pattern_def["severity"],
                "description": pattern_def["description"],
                "context_note": pattern_def.get("context_note", "")
            })

    return findings


def scan_mcp_config(target_dir):
    """Scan MCP configuration files for security issues."""
    findings = []
    mcp_files = list(target_dir.rglob(".mcp.json"))

    # Also check plugin.json for inline mcpServers
    plugin_json = target_dir / ".claude-plugin" / "plugin.json"
    if plugin_json.exists():
        try:
            data = json.loads(plugin_json.read_text(encoding="utf-8"))
            if "mcpServers" in data:
                mcp_files.append(plugin_json)
        except (json.JSONDecodeError, OSError):
            pass

    for mcp_file in mcp_files:
        try:
            content = mcp_file.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError:
            findings.append({
                "file": str(mcp_file),
                "line": 1,
                "line_content": "(invalid JSON)",
                "pattern_id": "MCP_001",
                "category": "network-abuse",
                "severity": "MEDIUM",
                "description": "Invalid JSON in MCP config file — may be corrupted or intentionally malformed",
                "context_note": "Cannot parse MCP config; manual review needed"
            })
            continue
        except OSError:
            continue

        # If it's plugin.json, narrow to the mcpServers section
        servers = data
        if "mcpServers" in data:
            mcp_ref = data["mcpServers"]
            if isinstance(mcp_ref, dict):
                servers = mcp_ref
            else:
                continue  # It's a path reference, skip

        if not isinstance(servers, dict):
            continue

        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue

            url = server_config.get("url", "")
            server_type = server_config.get("type", "")

            # Check for HTTP (not HTTPS)
            if isinstance(url, str) and url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                findings.append({
                    "file": str(mcp_file),
                    "line": 1,
                    "line_content": f'Server "{server_name}": {url[:100]}',
                    "pattern_id": "MCP_002",
                    "category": "network-abuse",
                    "severity": "HIGH",
                    "description": f"MCP server '{server_name}' uses HTTP instead of HTTPS",
                    "context_note": "Unencrypted MCP connections expose tool data in transit"
                })

            # Check for hardcoded credentials in URL
            if isinstance(url, str) and re.search(r'://[^/]*:[^/]*@', url):
                findings.append({
                    "file": str(mcp_file),
                    "line": 1,
                    "line_content": f'Server "{server_name}": (URL with embedded credentials)',
                    "pattern_id": "MCP_003",
                    "category": "credential-theft",
                    "severity": "CRITICAL",
                    "description": f"MCP server '{server_name}' has credentials embedded in URL",
                    "context_note": "Credentials in URLs are visible in logs and process lists"
                })

            # Check headers for hardcoded tokens (not env var references)
            headers = server_config.get("headers", {})
            if isinstance(headers, dict):
                for header_name, header_value in headers.items():
                    if isinstance(header_value, str) and not header_value.startswith("${") and "bearer" in header_name.lower() + header_value.lower():
                        findings.append({
                            "file": str(mcp_file),
                            "line": 1,
                            "line_content": f'Server "{server_name}" header "{header_name}": (hardcoded)',
                            "pattern_id": "MCP_004",
                            "category": "credential-theft",
                            "severity": "HIGH",
                            "description": f"MCP server '{server_name}' has hardcoded auth token (not env var reference)",
                            "context_note": "Use ${ENV_VAR} references for credentials instead of hardcoding"
                        })

    return findings


def scan_hook_config(target_dir):
    """Scan hook configuration files for security issues."""
    findings = []
    hook_files = list(target_dir.rglob("hooks.json"))

    for hook_file in hook_files:
        try:
            content = hook_file.read_text(encoding="utf-8")
            data = json.loads(content)
        except (json.JSONDecodeError, OSError):
            continue

        hooks = data.get("hooks", data)
        if not isinstance(hooks, dict):
            continue

        for event_name, event_hooks in hooks.items():
            if not isinstance(event_hooks, list):
                continue

            for hook_entry in event_hooks:
                if not isinstance(hook_entry, dict):
                    continue

                matcher = hook_entry.get("matcher", "")
                hook_list = hook_entry.get("hooks", [])

                # Check for wildcard matcher
                if matcher == "*" or matcher == ".*":
                    findings.append({
                        "file": str(hook_file),
                        "line": 1,
                        "line_content": f'Event "{event_name}" matcher: "{matcher}"',
                        "pattern_id": "HOOK_010",
                        "category": "hook-hijacking",
                        "severity": "HIGH",
                        "description": f"Wildcard matcher on {event_name} — intercepts ALL tool calls",
                        "context_note": "Wildcard hooks see all data; should be scoped to specific tools"
                    })

                # Check hook commands for suspicious patterns
                for hook_def in hook_list:
                    if not isinstance(hook_def, dict):
                        continue
                    cmd = hook_def.get("command", "")
                    if isinstance(cmd, str):
                        # Check for external URLs in hook commands
                        if re.search(r'https?://(?!localhost|127\.0\.0\.1)', cmd):
                            findings.append({
                                "file": str(hook_file),
                                "line": 1,
                                "line_content": f'Hook command: {cmd[:150]}',
                                "pattern_id": "HOOK_011",
                                "category": "hook-hijacking",
                                "severity": "HIGH",
                                "description": f"Hook command references external URL in {event_name}",
                                "context_note": "Hooks sending data to external URLs may be exfiltrating"
                            })

    return findings


def scan_structure(target_dir, files):
    """Scan plugin file structure for suspicious patterns."""
    findings = []

    suspicious_names = re.compile(
        r'(?:keylog|exfil|backdoor|reverse.?shell|payload|exploit|c2|beacon|implant|rootkit|trojan|malware|rat[_\-.])',
        re.IGNORECASE
    )

    suspicious_extensions = {".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".vbs", ".scr", ".com"}

    for f in files:
        name = f.name
        ext = f.suffix.lower()

        # Check for suspiciously named files
        if suspicious_names.search(name):
            findings.append({
                "file": str(f),
                "line": 0,
                "line_content": f"Filename: {name}",
                "pattern_id": "STRUCT_001",
                "category": "code-execution",
                "severity": "HIGH",
                "description": f"Suspiciously named file: {name}",
                "context_note": "File name suggests malicious intent; investigate contents"
            })

        # Check for executable binaries in plugin
        if ext in suspicious_extensions:
            findings.append({
                "file": str(f),
                "line": 0,
                "line_content": f"Binary: {name}",
                "pattern_id": "STRUCT_002",
                "category": "code-execution",
                "severity": "HIGH",
                "description": f"Executable binary found in plugin: {name}",
                "context_note": "Plugins should use interpreted scripts, not compiled binaries"
            })

    return findings


def determine_risk_level(severity_counts):
    """Determine overall risk level from severity counts."""
    if severity_counts.get("CRITICAL", 0) > 0:
        return "DANGER"
    if severity_counts.get("HIGH", 0) >= 3:
        return "DANGER"
    if severity_counts.get("HIGH", 0) > 0:
        return "CAUTION"
    if severity_counts.get("MEDIUM", 0) >= 3:
        return "CAUTION"
    if severity_counts.get("MEDIUM", 0) > 0:
        return "CAUTION"
    return "SAFE"


def generate_report(target_dir):
    """Generate the complete scan report."""
    target = Path(target_dir).resolve()

    if not target.exists():
        return {"error": f"Path does not exist: {target}"}

    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}

    # Load external signatures
    ext_patterns, ext_multiline, ext_malicious = load_external_signatures()

    # Collect files
    files, skipped_count = collect_files(target)

    # Merge built-in + external patterns (avoid duplicate IDs)
    builtin_ids = {p["id"] for p in PATTERNS}
    merged_patterns = list(PATTERNS)
    for ep in ext_patterns:
        if ep["id"] not in builtin_ids:
            merged_patterns.append(ep)

    builtin_ml_ids = {p["id"] for p in MULTILINE_PATTERNS}
    merged_multiline = list(MULTILINE_PATTERNS)
    for em in ext_multiline:
        if em["id"] not in builtin_ml_ids:
            merged_multiline.append(em)

    builtin_mal_ids = {s["id"] for s in KNOWN_MALICIOUS_SIGNATURES}
    merged_malicious = list(KNOWN_MALICIOUS_SIGNATURES)
    for ems in ext_malicious:
        if ems["id"] not in builtin_mal_ids:
            merged_malicious.append(ems)

    # Run all scans
    all_findings = []

    # Pattern-based file scanning (built-in + external)
    for f in files:
        all_findings.extend(scan_file(f, merged_patterns, merged_multiline))

    # MCP config scanning
    all_findings.extend(scan_mcp_config(target))

    # Hook config scanning
    all_findings.extend(scan_hook_config(target))

    # Structure scanning
    all_findings.extend(scan_structure(target, files))

    # Known malicious signature scanning (built-in + external)
    all_findings.extend(scan_known_malicious(target, files, merged_malicious))

    # Deduplicate findings (same file + line + pattern_id)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f["file"], f["line"], f["pattern_id"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Count by severity and category
    severity_counts = {}
    category_counts = {}
    for f in unique_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

    # Determine risk level
    overall_risk = determine_risk_level(severity_counts)

    # Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    # Number findings
    for i, f in enumerate(unique_findings, start=1):
        f["id"] = i

    report = {
        "scan_metadata": {
            "target": str(target),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_version": SCANNER_VERSION,
            "files_scanned": len(files),
            "files_skipped": skipped_count,
            "signatures": {
                "builtin_patterns": len(PATTERNS) + len(MULTILINE_PATTERNS),
                "builtin_malicious": len(KNOWN_MALICIOUS_SIGNATURES),
                "external_patterns": len(ext_patterns) + len(ext_multiline),
                "external_malicious": len(ext_malicious),
                "total": len(merged_patterns) + len(merged_multiline) + len(merged_malicious)
            }
        },
        "summary": {
            "overall_risk": overall_risk,
            "total_findings": len(unique_findings),
            "by_severity": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
                "INFO": severity_counts.get("INFO", 0)
            },
            "by_category": category_counts
        },
        "findings": unique_findings
    }

    return report


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: scan_plugin.py <path-to-plugin-directory>",
            "example": "python scan_plugin.py ~/.claude/plugins/some-plugin"
        }, indent=2))
        sys.exit(0)

    target = sys.argv[1]
    report = generate_report(target)
    print(json.dumps(report, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()

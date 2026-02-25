#!/usr/bin/env python3
"""
Signature Update Script — fetches latest malicious signatures for MCP Scanner.

Downloads updated signatures from a remote source and merges them with the
local signatures.json file. Preserves any custom local signatures added by
the user.

Usage:
    python update_signatures.py                          # Fetch and merge latest signatures
    python update_signatures.py --url <custom-url>       # Use a custom signature source
    python update_signatures.py --add-pattern <json>     # Add a single pattern manually
    python update_signatures.py --add-malicious <json>   # Add a known malicious signature manually
    python update_signatures.py --show                   # Show current signature stats
    python update_signatures.py --validate               # Validate signatures.json

Signature file: ~/.claude/plugins/mcp-scanner/signatures/signatures.json
"""

import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# Default remote URL (can be overridden with --url flag or feed_config.json)
# Users should host their own signature feed or use a community-maintained one
DEFAULT_SIGNATURE_URL = ""
SIGNATURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signatures")
SIGNATURES_FILE = os.path.join(SIGNATURES_DIR, "signatures.json")
FEED_CONFIG_FILE = os.path.join(SIGNATURES_DIR, "feed_config.json")
BACKUP_SUFFIX = ".backup"


def get_feed_url():
    """Get the configured feed URL from feed_config.json or default."""
    if os.path.exists(FEED_CONFIG_FILE):
        try:
            with open(FEED_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            return config.get("url", DEFAULT_SIGNATURE_URL)
        except (json.JSONDecodeError, IOError):
            pass
    return DEFAULT_SIGNATURE_URL


def load_signatures(path=None):
    """Load signatures from the JSON file."""
    path = path or SIGNATURES_FILE
    if not os.path.exists(path):
        return {"version": "0.0.0", "patterns": [], "multiline_patterns": [], "known_malicious": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading signatures: {e}")
        return None


def save_signatures(data, path=None):
    """Save signatures to the JSON file."""
    path = path or SIGNATURES_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def backup_signatures():
    """Create a backup of the current signatures file."""
    if os.path.exists(SIGNATURES_FILE):
        backup_path = SIGNATURES_FILE + BACKUP_SUFFIX
        shutil.copy2(SIGNATURES_FILE, backup_path)
        return backup_path
    return None


def validate_pattern(pattern):
    """Validate a single pattern definition."""
    errors = []
    required_fields = ["id", "category", "severity", "description", "regex"]
    for field in required_fields:
        if field not in pattern:
            errors.append(f"Missing required field: {field}")

    if "regex" in pattern:
        try:
            re.compile(pattern["regex"])
        except re.error as e:
            errors.append(f"Invalid regex '{pattern['regex']}': {e}")

    if "severity" in pattern:
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if pattern["severity"] not in valid_severities:
            errors.append(f"Invalid severity '{pattern['severity']}' — must be one of {valid_severities}")

    return errors


def validate_malicious_signature(sig):
    """Validate a known malicious signature definition."""
    errors = []
    required_fields = ["id", "name", "description", "severity", "fingerprints", "min_matches"]
    for field in required_fields:
        if field not in sig:
            errors.append(f"Missing required field: {field}")

    if "fingerprints" in sig:
        if not isinstance(sig["fingerprints"], list) or len(sig["fingerprints"]) == 0:
            errors.append("fingerprints must be a non-empty list of regex strings")
        else:
            for i, fp in enumerate(sig["fingerprints"]):
                try:
                    re.compile(fp)
                except re.error as e:
                    errors.append(f"Invalid fingerprint regex [{i}] '{fp}': {e}")

    if "min_matches" in sig:
        if not isinstance(sig["min_matches"], int) or sig["min_matches"] < 1:
            errors.append("min_matches must be a positive integer")

    return errors


def validate_signatures(data):
    """Validate the entire signatures file."""
    all_errors = []
    seen_ids = set()

    for section_name, validator in [
        ("patterns", validate_pattern),
        ("multiline_patterns", validate_pattern),
    ]:
        for i, entry in enumerate(data.get(section_name, [])):
            entry_id = entry.get("id", f"<missing-id-{i}>")
            if entry_id in seen_ids:
                all_errors.append(f"[{section_name}] Duplicate ID: {entry_id}")
            seen_ids.add(entry_id)
            errors = validator(entry)
            for e in errors:
                all_errors.append(f"[{section_name}][{entry_id}] {e}")

    for i, sig in enumerate(data.get("known_malicious", [])):
        sig_id = sig.get("id", f"<missing-id-{i}>")
        if sig_id in seen_ids:
            all_errors.append(f"[known_malicious] Duplicate ID: {sig_id}")
        seen_ids.add(sig_id)
        errors = validate_malicious_signature(sig)
        for e in errors:
            all_errors.append(f"[known_malicious][{sig_id}] {e}")

    return all_errors


def merge_signatures(local, remote):
    """Merge remote signatures into local, preserving local-only entries."""
    merged = {
        "version": remote.get("version", local.get("version", "0.0.0")),
        "updated": datetime.now(timezone.utc).isoformat(),
        "source": remote.get("source", "remote"),
        "description": local.get("description", ""),
    }

    for section in ["patterns", "multiline_patterns", "known_malicious"]:
        local_entries = {e["id"]: e for e in local.get(section, [])}
        remote_entries = {e["id"]: e for e in remote.get(section, [])}

        # Start with remote entries (they override local for same ID)
        combined = dict(remote_entries)

        # Add local-only entries (IDs not in remote)
        for entry_id, entry in local_entries.items():
            if entry_id not in combined:
                combined[entry_id] = entry

        merged[section] = list(combined.values())

    return merged


def fetch_remote_signatures(url):
    """Fetch signatures from a remote URL."""
    # Use urllib from stdlib to avoid dependency on requests
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MCP-Scanner/1.1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data
    except urllib.error.URLError as e:
        print(f"Error fetching signatures from {url}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing remote signatures: {e}")
        return None


def show_stats():
    """Display statistics about current signatures."""
    data = load_signatures()
    if data is None:
        print("Could not load signatures file.")
        return

    print(f"MCP Scanner Signatures")
    print(f"{'=' * 50}")
    print(f"  Version:            {data.get('version', 'unknown')}")
    print(f"  Last updated:       {data.get('updated', 'unknown')}")
    print(f"  Source:             {data.get('source', 'unknown')}")
    print()

    patterns = data.get("patterns", [])
    multiline = data.get("multiline_patterns", [])
    malicious = data.get("known_malicious", [])

    print(f"  Line patterns:      {len(patterns)}")
    print(f"  Multi-line patterns: {len(multiline)}")
    print(f"  Known malicious:    {len(malicious)}")
    print(f"  Total signatures:   {len(patterns) + len(multiline) + len(malicious)}")
    print()

    # Breakdown by category
    categories = {}
    for p in patterns + multiline:
        cat = p.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
    if malicious:
        categories["known-malicious"] = len(malicious)

    print("  By category:")
    for cat, count in sorted(categories.items()):
        print(f"    {cat}: {count}")

    # Breakdown by severity
    severities = {}
    for p in patterns + multiline:
        sev = p.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1
    for m in malicious:
        sev = m.get("severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1

    print()
    print("  By severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severities:
            print(f"    {sev}: {severities[sev]}")

    print(f"\n  Signatures file: {SIGNATURES_FILE}")


def add_entry(json_str, section):
    """Add a single entry to a section of the signatures file."""
    try:
        entry = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return False

    data = load_signatures()
    if data is None:
        return False

    # Validate
    if section in ("patterns", "multiline_patterns"):
        errors = validate_pattern(entry)
    elif section == "known_malicious":
        errors = validate_malicious_signature(entry)
    else:
        print(f"Unknown section: {section}")
        return False

    if errors:
        print(f"Validation errors:")
        for e in errors:
            print(f"  - {e}")
        return False

    # Check for duplicate ID
    existing_ids = {e["id"] for e in data.get(section, [])}
    if entry["id"] in existing_ids:
        print(f"Entry with ID '{entry['id']}' already exists. Remove it first or use a different ID.")
        return False

    if section not in data:
        data[section] = []
    data[section].append(entry)
    data["updated"] = datetime.now(timezone.utc).isoformat()

    backup_signatures()
    save_signatures(data)
    print(f"Added {entry['id']} to {section}. Total {section}: {len(data[section])}")
    return True


def main():
    if len(sys.argv) < 2:
        # Default: show help
        print(__doc__)
        return

    arg = sys.argv[1]

    if arg == "--show":
        show_stats()

    elif arg == "--validate":
        data = load_signatures()
        if data is None:
            print("Could not load signatures file.")
            sys.exit(1)
        errors = validate_signatures(data)
        if errors:
            print(f"Validation failed with {len(errors)} error(s):")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            total = (len(data.get("patterns", [])) +
                     len(data.get("multiline_patterns", [])) +
                     len(data.get("known_malicious", [])))
            print(f"Signatures valid. {total} total entries.")

    elif arg == "--add-pattern":
        if len(sys.argv) < 3:
            print("Usage: --add-pattern '<json-string>'")
            sys.exit(1)
        add_entry(sys.argv[2], "patterns")

    elif arg == "--add-malicious":
        if len(sys.argv) < 3:
            print("Usage: --add-malicious '<json-string>'")
            sys.exit(1)
        add_entry(sys.argv[2], "known_malicious")

    elif arg == "--set-feed":
        if len(sys.argv) < 3:
            print("Usage: --set-feed <url>")
            print("Sets the default signature feed URL for future --fetch calls.")
            sys.exit(1)
        url = sys.argv[2]
        os.makedirs(SIGNATURES_DIR, exist_ok=True)
        config = {"url": url, "set_at": datetime.now(timezone.utc).isoformat()}
        with open(FEED_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        print(f"Feed URL set: {url}")
        print(f"Config saved to: {FEED_CONFIG_FILE}")
        print("Run 'update_signatures.py --fetch' to download signatures from this feed.")

    elif arg == "--url" or arg == "--fetch":
        url = sys.argv[2] if (len(sys.argv) > 2 and not sys.argv[2].startswith("--")) else get_feed_url()
        if not url:
            print("No signature URL configured.")
            print()
            print("Set up a feed URL first:")
            print("  python update_signatures.py --set-feed https://raw.githubusercontent.com/YOUR_USER/mcp-signatures/main/signatures.json")
            print()
            print("Or provide a URL directly:")
            print("  python update_signatures.py --url https://your-server.com/signatures.json")
            print()
            print("Or add patterns manually:")
            print('  python update_signatures.py --add-pattern \'{"id":"MY_001","category":"prompt-injection","severity":"HIGH","description":"My pattern","regex":"my_regex","file_types":[".py"]}\'')
            sys.exit(1)

        print(f"Fetching signatures from: {url}")
        remote = fetch_remote_signatures(url)
        if remote is None:
            print("Failed to fetch remote signatures.")
            sys.exit(1)

        # Validate remote signatures
        errors = validate_signatures(remote)
        if errors:
            print(f"Remote signatures have {len(errors)} validation error(s):")
            for e in errors[:10]:
                print(f"  - {e}")
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more")
            print("Aborting merge. Fix the remote signatures and try again.")
            sys.exit(1)

        # Load local and merge
        local = load_signatures()
        if local is None:
            local = {"patterns": [], "multiline_patterns": [], "known_malicious": []}

        backup_path = backup_signatures()
        merged = merge_signatures(local, remote)
        save_signatures(merged)

        # Report results
        local_total = (len(local.get("patterns", [])) +
                       len(local.get("multiline_patterns", [])) +
                       len(local.get("known_malicious", [])))
        merged_total = (len(merged.get("patterns", [])) +
                        len(merged.get("multiline_patterns", [])) +
                        len(merged.get("known_malicious", [])))
        new_count = merged_total - local_total

        print(f"Signatures updated successfully.")
        print(f"  Previous: {local_total} signatures (v{local.get('version', '?')})")
        print(f"  Current:  {merged_total} signatures (v{merged.get('version', '?')})")
        print(f"  New:      {new_count} added")
        if backup_path:
            print(f"  Backup:   {backup_path}")

    else:
        print(f"Unknown argument: {arg}")
        print("Usage: update_signatures.py [--show | --validate | --fetch | --url <url> | --set-feed <url> | --add-pattern <json> | --add-malicious <json>]")
        sys.exit(1)


if __name__ == "__main__":
    main()

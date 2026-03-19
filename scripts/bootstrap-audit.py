#!/usr/bin/env python3
"""Read-only bootstrap content audit for OpenClaw workspace files."""

import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path

DEFAULT_WORKSPACE = "/home/openclaw/.openclaw/workspace/"
DEFAULT_DEPLOYMENT_PROFILE = "/home/openclaw/.openclaw/extensions/deployment-profile.json"
BOOTSTRAP_FILES = [
    "SOUL.md",
    "AGENTS.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "USER.md",
    "TOOLS.md",
    "BOOTSTRAP.md",
    "MEMORY.md",
]
PER_FILE_LIMIT = 20_000
TOTAL_LIMIT = 150_000
SERVICE_REF_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "check",
    "do",
    "file",
    "for",
    "from",
    "has",
    "health",
    "if",
    "in",
    "is",
    "it",
    "its",
    "management",
    "may",
    "name",
    "no",
    "not",
    "of",
    "on",
    "or",
    "out",
    "per",
    "restart",
    "restarts",
    "running",
    "so",
    "start",
    "status",
    "stop",
    "the",
    "to",
    "up",
    "via",
    "was",
    "we",
    "will",
    "with",
    "you",
    "your",
}
MODEL_FILE_EXTENSIONS = (".json", ".md", ".py", ".sh", ".db", ".log")


def normalize_heading(text):
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    return normalized


def parse_headings(content):
    headings = []
    for line in content.splitlines():
        match = re.match(r"^(#{2,3})\s+(.+?)\s*$", line)
        if match:
            heading_text = match.group(2).strip()
            headings.append((heading_text, normalize_heading(heading_text)))
    return headings


def parse_paragraphs(content):
    paragraphs = []
    current = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            if len(current) >= 3:
                paragraphs.append("\n".join(current))
            current = []
            continue
        if stripped.startswith("#"):
            if len(current) >= 3:
                paragraphs.append("\n".join(current))
            current = []
            continue
        current.append(stripped)
    if len(current) >= 3:
        paragraphs.append("\n".join(current))
    return paragraphs


def owner_for_content(text):
    lower = text.lower()
    if any(k in lower for k in ["identity", "policy", "authority", "acip", "injection"]):
        return "SOUL.md"
    if any(k in lower for k in ["tool", "command", "execution"]):
        return "TOOLS.md"
    if any(k in lower for k in ["heartbeat", "daily", "weekly", "cron", "recurring"]):
        return "HEARTBEAT.md"
    return "AGENTS.md"


def load_deployment_profile(path):
    profile_file = Path(path)
    if not profile_file.exists():
        return None
    try:
        return json.loads(profile_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def collect_service_model_reference_data(profile):
    service_names = set()
    service_ports = set()
    model_names = set()

    if not profile:
        return service_names, service_ports, model_names

    services = profile.get("services", {})
    if isinstance(services, dict):
        for name, cfg in services.items():
            service_names.add(str(name))
            if isinstance(cfg, dict):
                for key in ("port", "ports"):
                    if key in cfg:
                        value = cfg[key]
                        if isinstance(value, list):
                            for item in value:
                                if str(item).isdigit():
                                    service_ports.add(str(item))
                        elif str(value).isdigit():
                            service_ports.add(str(value))
    elif isinstance(services, list):
        for item in services:
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    service_names.add(str(name))
                port = item.get("port")
                if port is not None and str(port).isdigit():
                    service_ports.add(str(port))

    model_routing = profile.get("model_routing", {})
    if isinstance(model_routing, dict):
        for key, value in model_routing.items():
            model_names.add(str(key))
            if isinstance(value, str):
                model_names.add(value)
            elif isinstance(value, dict):
                for candidate in value.values():
                    if isinstance(candidate, str):
                        model_names.add(candidate)
            elif isinstance(value, list):
                for candidate in value:
                    if isinstance(candidate, str):
                        model_names.add(candidate)

    return service_names, service_ports, model_names


def extract_candidate_refs(content):
    service_refs = set()
    model_refs = set()
    ports = set()
    paths = set()

    for match in re.finditer(r"\bservice\s*[:=]\s*([A-Za-z0-9._-]+)", content, re.IGNORECASE):
        service_refs.add(match.group(1))
    for match in re.finditer(r"\bservices?\s+([A-Za-z0-9._-]+)", content, re.IGNORECASE):
        service_refs.add(match.group(1))

    service_refs = {
        ref for ref in service_refs if ref and ref.lower() not in SERVICE_REF_STOPWORDS
    }

    for match in re.finditer(r"\bport\s*[:=]?\s*(\d{2,5})\b", content, re.IGNORECASE):
        ports.add(match.group(1))

    for match in re.finditer(r"\bmodel\s*[:=]\s*([A-Za-z0-9._:-]+)", content, re.IGNORECASE):
        model_refs.add(match.group(1))

    model_keywords = ("gpt", "claude", "gemini", "llama", "mistral")
    for token in re.findall(r"\b[A-Za-z0-9._:-]{4,}\b", content):
        lower = token.lower()
        has_keyword = any(keyword in lower for keyword in model_keywords)
        has_provider_prefix = "/" in token
        has_version_suffix = bool(re.search(r"\d", token))
        if lower.endswith(MODEL_FILE_EXTENSIONS):
            continue
        if has_keyword and (has_provider_prefix or has_version_suffix):
            model_refs.add(token)

    for match in re.finditer(r"(/[-A-Za-z0-9_./~]+)", content):
        path_text = match.group(1).rstrip(".,:;`)")
        if len(path_text) > 1:
            paths.add(path_text)

    return service_refs, model_refs, ports, paths


def check_security_coverage(files_map, issues):
    soul = files_map.get("SOUL.md", "")
    agents = files_map.get("AGENTS.md", "")

    soul_headings = parse_headings(soul)
    headings_text = [h[0].lower() for h in soul_headings]
    first_50 = "\n".join(soul.splitlines()[:50]).lower()

    has_acip = any(("acip" in h or "injection" in h) for h in headings_text)
    has_operator = any(
        (
            "operator" in h
            or "authority" in h
            or "belong" in h
            or "owner" in h
            or "adam" in h
        )
        for h in headings_text
    ) or (
        "operator" in first_50
        or "authority" in first_50
        or "belong" in first_50
        or "owner" in first_50
        or "adam" in first_50
    )

    agent_headings = [h[0].lower() for h in parse_headings(agents)]
    has_tool_policy = any("tool" in h for h in agent_headings)

    checks = [
        (has_acip, "SOUL.md", "ACIP injection defense section"),
        (has_operator, "SOUL.md", "single-operator authority declaration"),
        (has_tool_policy, "AGENTS.md", "tool execution policy section"),
    ]

    for present, file_name, label in checks:
        if present:
            issues.append(
                {
                    "category": "security-coverage",
                    "severity": "info",
                    "files": [file_name],
                    "description": f"Confirmed presence of required {label}.",
                    "suggestion": "No action needed.",
                }
            )
        else:
            issues.append(
                {
                    "category": "security-coverage",
                    "severity": "critical",
                    "files": [file_name],
                    "description": f"Missing required {label}.",
                    "suggestion": f"Add a dedicated heading and section for {label} in {file_name}.",
                }
            )


def main():
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(DEFAULT_WORKSPACE)
    deployment_profile_path = Path(DEFAULT_DEPLOYMENT_PROFILE)
    output_path = workspace / "bootstrap-audit.json"

    files_map = {}
    sizes = {}
    issues = []

    for name in BOOTSTRAP_FILES:
        file_path = workspace / name
        if file_path.exists() and file_path.is_file():
            try:
                content = file_path.read_text(encoding="utf-8")
            except OSError:
                content = ""
            files_map[name] = content
            sizes[name] = file_path.stat().st_size

    # 1) Cross-file duplication checks
    heading_index = defaultdict(list)
    paragraph_index = []

    for name, content in files_map.items():
        for original, normalized in parse_headings(content):
            if normalized:
                heading_index[normalized].append((name, original))
        for paragraph in parse_paragraphs(content):
            paragraph_index.append((name, paragraph))

    for normalized, entries in heading_index.items():
        files = sorted({entry[0] for entry in entries})
        if len(files) > 1:
            heading_text = entries[0][1]
            recommended_owner = owner_for_content(heading_text)
            issues.append(
                {
                    "category": "duplication",
                    "severity": "warning",
                    "files": files,
                    "description": f"Heading duplication across files for section '{heading_text}'.",
                    "suggestion": f"Consolidate this section in {recommended_owner} and replace duplicates with references.",
                }
            )

    seen_pairs = set()
    for idx, (file_a, para_a) in enumerate(paragraph_index):
        for file_b, para_b in paragraph_index[idx + 1 :]:
            if file_a == file_b:
                continue
            pair_key = tuple(sorted([file_a, file_b])) + (
                para_a[:80],
                para_b[:80],
            )
            if pair_key in seen_pairs:
                continue
            ratio = SequenceMatcher(None, para_a, para_b).ratio()
            if ratio >= 0.92:
                seen_pairs.add(pair_key)
                recommendation = owner_for_content(para_a)
                issues.append(
                    {
                        "category": "duplication",
                        "severity": "warning",
                        "files": sorted([file_a, file_b]),
                        "description": "Nearly identical 3+ line paragraph appears in multiple bootstrap files.",
                        "suggestion": f"Keep canonical copy in {recommendation} and cross-reference from other files.",
                    }
                )

    # 2) Stale references
    profile = load_deployment_profile(deployment_profile_path)
    service_names, service_ports, model_names = collect_service_model_reference_data(profile)

    for name, content in files_map.items():
        service_refs, model_refs, ports, paths = extract_candidate_refs(content)

        if profile is not None:
            for service in sorted(service_refs):
                if service not in service_names:
                    issues.append(
                        {
                            "category": "stale-reference",
                            "severity": "warning",
                            "files": [name],
                            "description": f"Service reference '{service}' not found in deployment profile services.",
                            "suggestion": "Update the service name or deployment profile to match current deployment.",
                        }
                    )
            for port in sorted(ports):
                if service_ports and port not in service_ports:
                    issues.append(
                        {
                            "category": "stale-reference",
                            "severity": "warning",
                            "files": [name],
                            "description": f"Port reference '{port}' not found in deployment profile services.",
                            "suggestion": "Update stale port references to current service ports.",
                        }
                    )
            for model in sorted(model_refs):
                if model not in model_names:
                    issues.append(
                        {
                            "category": "stale-reference",
                            "severity": "warning",
                            "files": [name],
                            "description": f"Model reference '{model}' not found in deployment profile model_routing.",
                            "suggestion": "Align model references with model_routing entries.",
                        }
                    )

        for path_value in sorted(paths):
            expanded = os.path.expanduser(path_value)
            if not os.path.exists(expanded):
                issues.append(
                    {
                        "category": "stale-reference",
                        "severity": "info",
                        "files": [name],
                        "description": f"Path reference '{path_value}' does not exist on disk.",
                        "suggestion": "Update or remove stale path references if no longer valid.",
                    }
                )

    # 3) Bloat detection and token budget
    token_budget_files = []
    total_bytes = 0

    for name in sorted(files_map.keys()):
        size_bytes = sizes[name]
        estimated_tokens = int(size_bytes / 4)
        pct_of_limit = round((size_bytes / PER_FILE_LIMIT) * 100, 2)
        total_bytes += size_bytes
        token_budget_files.append(
            {
                "name": name,
                "size_bytes": size_bytes,
                "estimated_tokens": estimated_tokens,
                "pct_of_limit": pct_of_limit,
            }
        )

        if size_bytes >= int(PER_FILE_LIMIT * 0.9):
            issues.append(
                {
                    "category": "bloat",
                    "severity": "critical",
                    "files": [name],
                    "description": f"{name} is at {pct_of_limit}% of per-file payload limit ({size_bytes} bytes).",
                    "suggestion": "Split or compress this file to reduce per-turn token overhead.",
                }
            )
        elif size_bytes >= int(PER_FILE_LIMIT * 0.8):
            issues.append(
                {
                    "category": "bloat",
                    "severity": "warning",
                    "files": [name],
                    "description": f"{name} exceeds 80% of per-file payload limit ({size_bytes} bytes).",
                    "suggestion": "Refactor and deduplicate content before this file exceeds hard limits.",
                }
            )

    total_pct = round((total_bytes / TOTAL_LIMIT) * 100, 2)
    total_tokens = int(total_bytes / 4)
    if total_bytes >= int(TOTAL_LIMIT * 0.7):
        issues.append(
            {
                "category": "bloat",
                "severity": "critical",
                "files": sorted(files_map.keys()),
                "description": f"Total bootstrap payload exceeds 70% of limit ({total_bytes} bytes).",
                "suggestion": "Reduce total bootstrap payload by moving recurring checks to automation and removing duplicates.",
            }
        )

    # 4) Heartbeat efficiency
    heartbeat = files_map.get("HEARTBEAT.md", "")
    for line in heartbeat.splitlines():
        item = line.strip()
        if not re.match(r"^(?:[-*]|\d+[.)])\s+", item):
            continue
        text = re.sub(r"^(?:[-*]|\d+[.)])\s+", "", item)
        lower = text.lower()
        if (
            any(k in lower for k in ["check", "verify", "confirm", "ensure"])
            and any(k in lower for k in ["exist", "file", "json", "service", "status", "port"])
        ):
            estimated_savings = max(40, int(len(text) / 4) * 2)
            issues.append(
                {
                    "category": "heartbeat-efficiency",
                    "severity": "info",
                    "files": ["HEARTBEAT.md"],
                    "description": f"Task '{text}' appears automatable as a cron/script check.",
                    "suggestion": f"Move this check to a scheduled script to save ~{estimated_savings} tokens per run.",
                }
            )

    # 5) Security coverage
    check_security_coverage(files_map, issues)

    # 6) Token budget report context (kept in report for downstream cost modeling)
    turns_per_day = 50
    cost_per_input_token = 0.0
    monthly_cost = total_tokens * 2 * turns_per_day * 30 * cost_per_input_token

    issue_counts = {
        "critical": sum(1 for issue in issues if issue["severity"] == "critical"),
        "warning": sum(1 for issue in issues if issue["severity"] == "warning"),
        "info": sum(1 for issue in issues if issue["severity"] == "info"),
    }

    report = {
        "summary": {
            "files_scanned": len(files_map),
            "total_issues": len(issues),
            "critical": issue_counts["critical"],
            "warning": issue_counts["warning"],
            "info": issue_counts["info"],
        },
        "issues": issues,
        "token_budget": {
            "files": token_budget_files,
            "total_bytes": total_bytes,
            "total_estimated_tokens": total_tokens,
            "total_pct_of_limit": total_pct,
            "monthly_cost": monthly_cost,
        },
        "last_run": datetime.now(timezone.utc).isoformat(),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Emit one-line run summary for wrapper log-based health validation.
    print(
        f"bootstrap-audit: status={report['summary']['critical'] == 0 and 'ok' or 'issues'} "
        f"files={report['summary']['files_scanned']} "
        f"critical={report['summary']['critical']} "
        f"warning={report['summary']['warning']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

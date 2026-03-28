#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

WORKSPACE = "/home/openclaw/.openclaw/workspace"
REPO_ROOT = "/home/openclaw/clawd-control"
EXTENSIONS_ROOT = "/home/openclaw/.openclaw/extensions"
BACKUP_ROOT = "/home/openclaw/.openclaw/backups/critical-files"
SESSIONS_DIR = "/home/openclaw/.openclaw/agents/main/sessions/"
PULSE_STATE = os.path.join(WORKSPACE, ".pulse-state.json")
SWEEP_STATUS = os.path.join(WORKSPACE, "sweep-status.json")
KILL_SWITCH_FILE = os.path.join(WORKSPACE, ".kill-switches.json")
BASELINE_FILE = os.path.join(WORKSPACE, ".db-size-baseline.json")
TASKS_DB = os.path.join(WORKSPACE, "tasks.db")
FACTS_DB = os.path.join(WORKSPACE, "facts.db")

EXTENSIONS_INCLUDE = [
    "camofox-browser",
    "credential-scanner",
    "graph-memory",
    "homoglyph-normalizer",
    "model-cortex",
    "security-hook",
    "stability",
    "telegram-dedupe",
]


def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ts(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def print_json(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True))
    sys.stdout.write("\n")


def atomic_write_json(path, payload):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=directory)
    try:
        json.dump(payload, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp.close()
        os.replace(tmp.name, path)
    finally:
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except OSError:
            pass


def file_sha256(path):
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def run_command(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def drift_detection():
    checked = 0
    drifted = []
    details = []

    for extension in EXTENSIONS_INCLUDE:
        runtime_ext = os.path.join(EXTENSIONS_ROOT, extension)
        repo_ext = os.path.join(REPO_ROOT, "extensions", extension)
        if not os.path.isdir(runtime_ext):
            continue
        if not os.path.isdir(repo_ext):
            details.append({"file": extension, "status": "skipped", "reason": "missing_repo_extension"})
            continue
        for root, _, files in os.walk(runtime_ext):
            for name in files:
                runtime_path = os.path.join(root, name)
                rel = os.path.relpath(runtime_path, runtime_ext)
                repo_path = os.path.join(repo_ext, rel)
                if not os.path.exists(repo_path):
                    details.append({"file": f"extensions/{extension}/{rel}", "status": "skipped", "reason": "missing_repo_file"})
                    continue
                checked += 1
                runtime_hash = file_sha256(runtime_path)
                repo_hash = file_sha256(repo_path)
                if runtime_hash != repo_hash:
                    drifted_name = f"extensions/{extension}/{rel}"
                    drifted.append(drifted_name)
                    details.append({"file": drifted_name, "status": "drift", "runtime_sha256": runtime_hash, "repo_sha256": repo_hash})
                else:
                    details.append({"file": f"extensions/{extension}/{rel}", "status": "ok"})

    tracked = run_command(["git", "-C", REPO_ROOT, "ls-files"]).stdout.splitlines()
    tracked_set = set(tracked)
    for rel in sorted(tracked_set):
        if rel.startswith("scripts/"):
            pass
        elif rel.endswith(".html") or rel.endswith(".js") or rel.endswith(".mjs"):
            pass
        else:
            continue
        checked += 1
        diff = run_command(["git", "-C", REPO_ROOT, "diff", "--name-only", "HEAD", "--", rel]).stdout.strip()
        if diff:
            drifted.append(rel)
            details.append({"file": rel, "status": "drift", "method": "git_diff_head"})
        else:
            details.append({"file": rel, "status": "ok", "method": "git_diff_head"})

    status = "alert" if drifted else "ok"
    message = "runtime/repo drift detected" if drifted else "runtime/repo drift check clean"
    print_json({
        "status": status,
        "message": message,
        "total_files_checked": checked,
        "files_with_drift": len(drifted),
        "drifted_filenames": sorted(set(drifted)),
        "details": details,
    })
    return 0


def touch_verify(directory):
    if not os.path.isdir(directory):
        return False, "missing_directory"
    marker = os.path.join(directory, f".audit-touch-{os.getpid()}-{int(time.time())}")
    try:
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("ok\n")
        with open(marker, "r", encoding="utf-8") as handle:
            content = handle.read().strip()
        os.remove(marker)
        return content == "ok", "ok" if content == "ok" else "readback_mismatch"
    except Exception as exc:
        try:
            if os.path.exists(marker):
                os.remove(marker)
        except OSError:
            pass
        return False, str(exc)


def sqlite_integrity(path):
    if not os.path.exists(path):
        return False, "missing_db"
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        row = cur.execute("PRAGMA integrity_check;").fetchone()
        conn.close()
        value = row[0] if row else ""
        if str(value).lower() == "ok":
            return True, "ok"
        return False, str(value)
    except Exception as exc:
        return False, str(exc)


def storage_health():
    alerts = []
    details = {}

    ok_workspace, msg_workspace = touch_verify(WORKSPACE)
    details["workspace_write_test"] = {"ok": ok_workspace, "message": msg_workspace}
    if not ok_workspace:
        alerts.append("workspace write test failed")

    ok_sessions, msg_sessions = touch_verify(SESSIONS_DIR)
    details["sessions_write_test"] = {"ok": ok_sessions, "message": msg_sessions}
    if not ok_sessions:
        alerts.append("sessions write test failed")

    df_output = run_command(["df", "-B1", "/home/openclaw"]).stdout.splitlines()
    free_bytes = 0
    if len(df_output) >= 2:
        parts = df_output[1].split()
        if len(parts) >= 4:
            try:
                free_bytes = int(parts[3])
            except ValueError:
                free_bytes = 0
    details["disk_free_bytes"] = free_bytes
    if free_bytes <= 1_000_000_000:
        alerts.append("disk headroom <= 1GB")

    fd_count = None
    pid_result = run_command(["pgrep", "-o", "-f", "openclaw"]).stdout.strip()
    if pid_result.isdigit():
        proc_fd = f"/proc/{pid_result}/fd"
        try:
            fd_count = len(os.listdir(proc_fd))
        except Exception:
            fd_count = None
    details["openclaw_fd_count"] = fd_count

    db_details = {}
    for db_path in [TASKS_DB, FACTS_DB]:
        ok, message = sqlite_integrity(db_path)
        db_details[db_path] = {"ok": ok, "message": message}
        if not ok:
            alerts.append(f"integrity check failed for {os.path.basename(db_path)}")
    details["db_integrity"] = db_details

    baseline = {}
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as handle:
                baseline = json.load(handle)
        except Exception:
            baseline = {}

    current_sizes = {}
    growth_alerts = []
    for db_path in [TASKS_DB, FACTS_DB]:
        if os.path.exists(db_path):
            current_size = os.path.getsize(db_path)
            current_sizes[db_path] = current_size
            previous_size = (baseline.get("sizes") or {}).get(db_path)
            if isinstance(previous_size, (int, float)) and previous_size > 0:
                growth = ((current_size - previous_size) / previous_size) * 100.0
                if growth > 30.0:
                    growth_alerts.append({"db": db_path, "growth_percent": round(growth, 2), "previous_size": previous_size, "current_size": current_size})

    if growth_alerts:
        alerts.append("database growth >30% detected")
    details["db_growth_alerts"] = growth_alerts

    atomic_write_json(BASELINE_FILE, {"updated_at": iso_now(), "sizes": current_sizes})

    status = "alert" if alerts else "ok"
    message = "; ".join(alerts) if alerts else "storage health checks passed"
    print_json({"status": status, "message": message, "details": details})
    return 0


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def age_minutes(ts):
    stamp = parse_ts(ts)
    if stamp is None:
        return None
    return (time.time() - stamp) / 60.0


def monitor_the_monitors():
    alerts = []
    details = {}

    pulse = read_json(PULSE_STATE)
    pulse_age = age_minutes(pulse.get("last_success_at"))
    details["pulse_last_success_age_minutes"] = None if pulse_age is None else round(pulse_age, 2)
    if pulse_age is None or pulse_age >= 10:
        alerts.append("pulse stale or missing")

    sweep = read_json(SWEEP_STATUS)
    sweep_age = age_minutes(sweep.get("last_success_at"))
    details["sweep_last_success_age_minutes"] = None if sweep_age is None else round(sweep_age, 2)
    if sweep_age is None or sweep_age >= 90:
        alerts.append("sweep stale or missing")

    journal = run_command(["journalctl", "-u", "openclaw.service", "--since", "60 minutes ago", "--no-pager", "-q"])
    heartbeat_count = len(re.findall(r"heartbeat", journal.stdout, flags=re.IGNORECASE))
    details["heartbeat_entries_last_60m"] = heartbeat_count
    if heartbeat_count == 0:
        alerts.append("no heartbeat entries in last 60 minutes")

    kill_switches = read_json(KILL_SWITCH_FILE)
    active = []
    for key, value in kill_switches.items() if isinstance(kill_switches, dict) else []:
        if isinstance(value, dict) and value.get("active"):
            activated_at = value.get("activated_at")
            duration = age_minutes(activated_at)
            active.append({
                "name": key,
                "reason": value.get("reason", ""),
                "activated_at": activated_at,
                "active_minutes": None if duration is None else round(duration, 2),
            })
    details["active_kill_switches"] = active

    status = "alert" if alerts else "ok"
    message = "; ".join(alerts) if alerts else "all monitor layers healthy"
    print_json({"status": status, "message": message, "details": details})
    return 0


def backup_rotation():
    details = []
    if not os.path.isdir(BACKUP_ROOT):
        print_json({"status": "ok", "message": "backup directory missing, nothing to prune", "groups": []})
        return 0

    files = [name for name in os.listdir(BACKUP_ROOT) if os.path.isfile(os.path.join(BACKUP_ROOT, name))]
    grouped = {}
    for name in files:
        prefix, _, suffix = name.rpartition(".")
        if not prefix or not suffix:
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", suffix):
            continue
        grouped.setdefault(prefix, []).append(name)

    for prefix, names in sorted(grouped.items()):
        names_sorted = sorted(names, reverse=True)
        removed = []
        for stale in names_sorted[7:]:
            path = os.path.join(BACKUP_ROOT, stale)
            try:
                os.remove(path)
                removed.append(stale)
            except OSError:
                pass
        retained = names_sorted[:7]
        all_present = True
        for keep in retained:
            if not os.path.exists(os.path.join(BACKUP_ROOT, keep)):
                all_present = False
        details.append({"file": prefix, "retained": retained, "removed": removed, "integrity_ok": all_present})

    bad = [item["file"] for item in details if not item["integrity_ok"]]
    status = "alert" if bad else "ok"
    message = "backup integrity issue for: " + ", ".join(bad) if bad else "critical file backup rotation complete"
    print_json({"status": status, "message": message, "groups": details})
    return 0


def append_recovery_log(args):
    log_path = os.path.join(WORKSPACE, ".recovery-log.jsonl")
    entry = {
        "timestamp": iso_now(),
        "check_id": args.check_id,
        "layer": args.layer,
        "action": args.action,
        "result": args.result,
    }
    existing = ""
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as handle:
            existing = handle.read()
    directory = os.path.dirname(log_path)
    tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=directory)
    try:
        tmp.write(existing)
        tmp.write(json.dumps(entry, sort_keys=True) + "\n")
        tmp.close()
        os.replace(tmp.name, log_path)
    finally:
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except OSError:
            pass
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Helpers for Layer 4 daily audit checks")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("drift-detection")
    subparsers.add_parser("storage-health")
    subparsers.add_parser("monitor-the-monitors")
    subparsers.add_parser("backup-rotation")

    append_parser = subparsers.add_parser("append-recovery-log")
    append_parser.add_argument("check_id")
    append_parser.add_argument("layer")
    append_parser.add_argument("action")
    append_parser.add_argument("result")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "drift-detection":
        return drift_detection()
    if args.command == "storage-health":
        return storage_health()
    if args.command == "monitor-the-monitors":
        return monitor_the_monitors()
    if args.command == "backup-rotation":
        return backup_rotation()
    if args.command == "append-recovery-log":
        return append_recovery_log(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

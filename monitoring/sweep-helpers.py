#!/usr/bin/env python3
import datetime
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request

WORKSPACE = "/home/openclaw/.openclaw/workspace"
SESSIONS_DIR = "/home/openclaw/.openclaw/agents/main/sessions/"
PULSE_CONFIG = WORKSPACE + "/.pulse-config.json"
CRITICAL_BASELINE = WORKSPACE + "/.critical-file-hashes.json"
CRITICAL_BACKUP_DIR = "/home/openclaw/.openclaw/backups/critical-files/"
CRITICAL_FILES = [
    "/usr/local/bin/check-security-health.sh",
    "/usr/local/bin/run-security-test.sh",
    "/usr/local/bin/openclaw-orphan-reaper.sh",
    WORKSPACE + "/SOUL.md",
]
ALLOWLIST_MARKERS = ["HEARTBEAT_OK", "NO_REPLY", "cron:"]


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


def print_json(obj):
    sys.stdout.write(json.dumps(obj, sort_keys=True))
    sys.stdout.write("\n")


def _atomic_write_json(path, data):
    directory = os.path.dirname(path) or "."
    tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=directory)
    try:
        json.dump(data, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp.close()
        os.replace(tmp.name, path)
    finally:
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except OSError:
            pass


def latest_session_file():
    candidates = []
    for root, dirs, files in os.walk(SESSIONS_DIR):
        dirs[:] = [d for d in dirs if "archive" not in d.lower() and "archived" not in d.lower()]
        for name in files:
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(root, name)
            if "archive" in path.lower() or "archived" in path.lower():
                continue
            try:
                candidates.append((os.path.getmtime(path), path))
            except OSError:
                continue
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def read_pulse_config():
    try:
        with open(PULSE_CONFIG, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def append_recovery_log(check_id, layer, action, result):
    log_path = WORKSPACE + "/.recovery-log.jsonl"
    entry = {
        "timestamp": iso_now(),
        "check_id": check_id,
        "layer": layer,
        "action": action,
        "result": result,
    }
    existing = ""
    if os.path.exists(log_path):
        existing = open(log_path, "r", encoding="utf-8").read()
    f = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=os.path.dirname(log_path))
    f.write(existing)
    f.write(json.dumps(entry, sort_keys=True) + "\n")
    f.close()
    os.replace(f.name, log_path)


def cron_liveness():
    now = datetime.datetime.now(datetime.timezone.utc)
    checks = [
        {"name": "watcher-status.json", "path": WORKSPACE + "/watcher-status.json", "fields": ["generated_at"], "max_stale_minutes": 90},
        {"name": "cost-sentinel-status.json", "path": WORKSPACE + "/cost-sentinel-status.json", "fields": ["timestamp", "generated_at", "last_success_at"], "max_stale_minutes": 1560},
        {"name": "cortex-sentinel-status.json", "path": WORKSPACE + "/cortex-sentinel-status.json", "fields": ["timestamp", "generated_at", "last_success_at"], "max_stale_minutes": 1560},
        {"name": ".pulse-state.json", "path": WORKSPACE + "/.pulse-state.json", "fields": ["last_success_at"], "max_stale_minutes": 10},
    ]
    failures = []
    details = []
    for chk in checks:
        path = chk["path"]
        name = chk["name"]
        fields = chk["fields"]
        limit = chk["max_stale_minutes"]
        if not os.path.exists(path):
            failures.append(name + ":missing-file")
            continue
        try:
            payload = json.load(open(path, "r", encoding="utf-8"))
        except Exception as exc:
            failures.append(name + ":parse-error:" + str(exc))
            continue
        stamp = None
        for field in fields:
            value = payload.get(field) if isinstance(payload, dict) else None
            if value:
                ts = parse_ts(value)
                if ts is not None:
                    stamp = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                    break
        if stamp is None:
            failures.append(name + ":missing-timestamp")
            continue
        stale = (now - stamp).total_seconds() / 60.0
        details.append({"name": name, "stale_minutes": round(stale, 2), "max_stale_minutes": limit})
        if stale > limit:
            failures.append(name + ":stale:" + str(int(stale)) + "m>" + str(limit) + "m")
    status = "alert" if failures else "ok"
    message = "cron liveness stale: " + "; ".join(failures) if failures else "cron liveness healthy"
    print_json({"status": status, "message": message, "failures": failures, "details": details})
    return 0


def token_anomaly():
    now = time.time()
    window_start = now - 1800
    target = latest_session_file()
    if not target:
        print_json({"status": "ok", "message": "no session files found", "assistant_turns": 0, "user_turns": 0, "session_file": None})
        return 0

    assistant_turns = 0
    user_turns = 0

    try:
        with open(target, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                role = entry.get("role")
                if role not in ("assistant", "user"):
                    continue
                content = str(entry.get("content", ""))
                if role == "assistant" and any(marker in content for marker in ALLOWLIST_MARKERS):
                    continue
                ts = parse_ts(entry.get("timestamp") or entry.get("created_at") or entry.get("time"))
                if ts is None or ts < window_start:
                    continue
                if role == "assistant":
                    assistant_turns += 1
                elif role == "user":
                    user_turns += 1
    except OSError as exc:
        print_json({"status": "alert", "message": "failed reading session file: " + str(exc), "assistant_turns": 0, "user_turns": 0, "session_file": target})
        return 1

    if assistant_turns > 5 and user_turns == 0:
        print_json({
            "status": "alert",
            "message": "token anomaly: " + str(assistant_turns) + " assistant turns, 0 user turns in 30min",
            "assistant_turns": assistant_turns,
            "user_turns": user_turns,
            "session_file": target,
        })
        return 0

    print_json({
        "status": "ok",
        "message": "token activity normal: assistant=" + str(assistant_turns) + ", user=" + str(user_turns) + " in 30min",
        "assistant_turns": assistant_turns,
        "user_turns": user_turns,
        "session_file": target,
    })
    return 0


def outbound_rate():
    # TEMPORARY: external observer via getUpdates. Replace with gateway ledger or remove by 2026-04-27.
    cfg = read_pulse_config()
    token = cfg.get("telegram_bot_token", "")
    if not token:
        print_json({"status": "alert", "message": "telegram token missing in .pulse-config.json", "message_count": 0})
        return 1

    now = int(time.time())
    window_start = now - 3600
    url = "https://api.telegram.org/bot" + token + "/getUpdates?offset=-100"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print_json({"status": "alert", "message": "telegram getUpdates failed: " + str(exc), "message_count": 0})
        return 1

    count = 0
    for update in payload.get("result", []):
        message = update.get("message") or update.get("edited_message") or {}
        date_value = message.get("date")
        sender = message.get("from", {}) if isinstance(message, dict) else {}
        if not isinstance(sender, dict) or not sender.get("is_bot"):
            continue
        if isinstance(date_value, int) and date_value >= window_start:
            count += 1

    status = "alert" if count > 20 else "ok"
    message = "outbound rate spike: " + str(count) + " messages in 60min" if status == "alert" else "outbound rate normal: " + str(count) + " messages in 60min"
    print_json({"status": status, "message": message, "message_count": count})
    return 0


def file_hashes():
    current = {"generated_at": iso_now(), "files": {}}
    missing = []
    changed = []

    for path in CRITICAL_FILES:
        if not os.path.exists(path):
            missing.append(path)
            continue
        sha = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                sha.update(chunk)
        current["files"][path] = {"sha256": sha.hexdigest(), "size": os.path.getsize(path)}

    if not os.path.exists(CRITICAL_BASELINE):
        _atomic_write_json(CRITICAL_BASELINE, current)
        print_json({"status": "ok", "message": "critical file hash baseline created", "missing_files": missing, "changed_files": changed, "baseline_created": True})
        return 0

    try:
        with open(CRITICAL_BASELINE, "r", encoding="utf-8") as handle:
            baseline = json.load(handle)
    except Exception as exc:
        print_json({"status": "alert", "message": "failed reading baseline: " + str(exc), "missing_files": missing, "changed_files": []})
        return 1

    baseline_files = baseline.get("files", {}) if isinstance(baseline, dict) else {}
    for path, meta in current["files"].items():
        expected = (baseline_files.get(path) or {}).get("sha256")
        if expected and expected != meta["sha256"]:
            changed.append(path)

    status = "alert" if missing or changed else "ok"
    if status == "alert":
        details = []
        if changed:
            details.append("changed=" + ",".join(changed))
        if missing:
            details.append("missing=" + ",".join(missing))
        message = "critical file hash alert: " + "; ".join(details)
    else:
        message = "critical file hashes unchanged"

    print_json({
        "status": status,
        "message": message,
        "missing_files": missing,
        "changed_files": changed,
        "baseline_created": False,
        "current_hashes": current,
    })
    return 0


def backup_critical_files():
    os.makedirs(CRITICAL_BACKUP_DIR, exist_ok=True)
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    copied = []

    for source in CRITICAL_FILES:
        if not os.path.exists(source):
            continue
        base = os.path.basename(source)
        destination = os.path.join(CRITICAL_BACKUP_DIR, base + "." + today)
        tmp_destination = destination + ".tmp." + str(os.getpid())
        shutil.copy2(source, tmp_destination)
        os.replace(tmp_destination, destination)
        copied.append(destination)

        pattern = os.path.join(CRITICAL_BACKUP_DIR, base + ".*")
        backups = sorted([p for p in glob.glob(pattern) if os.path.isfile(p)], key=os.path.getmtime, reverse=True)
        for stale in backups[7:]:
            try:
                os.remove(stale)
            except OSError:
                pass

    print_json({"status": "ok", "message": "critical file backups refreshed (" + str(len(copied)) + " copied)", "copied_files": copied})
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "append-recovery-log":
        check_id = sys.argv[2] if len(sys.argv) > 2 else ""
        layer = sys.argv[3] if len(sys.argv) > 3 else ""
        action = sys.argv[4] if len(sys.argv) > 4 else ""
        result = sys.argv[5] if len(sys.argv) > 5 else ""
        append_recovery_log(check_id, layer, action, result)
        return 0
    if cmd == "cron-liveness":
        return cron_liveness()
    if cmd == "token-anomaly":
        return token_anomaly()
    if cmd == "outbound-rate":
        return outbound_rate()
    if cmd == "file-hashes":
        return file_hashes()
    if cmd == "backup-critical-files":
        return backup_critical_files()
    if cmd in ("--help", "-h", "help", ""):
        print("Usage: sweep-helpers.py [cron-liveness|token-anomaly|outbound-rate|file-hashes|backup-critical-files|append-recovery-log]")
        return 0
    print("Unknown command: " + cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

import json, datetime, os, sys, tempfile, time

WORKSPACE = "/home/openclaw/.openclaw/workspace/"
SESSIONS = "/home/openclaw/.openclaw/sessions/"

def check_kill_switch_staleness():
    ks = json.load(open(WORKSPACE + ".kill-switches.json", "r", encoding="utf-8"))
    st = json.load(open(WORKSPACE + ".pulse-state.json", "r", encoding="utf-8"))
    now = datetime.datetime.now(datetime.timezone.utc)
    reminders = st.get("kill_switch_reminders", {})
    changed = False
    for k, v in ks.items():
        if not isinstance(v, dict) or not v.get("active") or not v.get("activated_at"):
            continue
        activated = datetime.datetime.fromisoformat(str(v["activated_at"]).replace("Z", "+00:00"))
        if (now - activated).total_seconds() < 43200:
            continue
        last = reminders.get(k)
        send = True
        if last:
            last_dt = datetime.datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            send = (now - last_dt).total_seconds() >= 43200
        if send:
            print(k)
            reminders[k] = now.isoformat().replace("+00:00", "Z")
            changed = True
    if changed:
        st["kill_switch_reminders"] = reminders
        p = WORKSPACE + ".pulse-state.json"
        f = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=os.path.dirname(p))
        json.dump(st, f, indent=2, sort_keys=True)
        f.write("\n")
        f.close()
        os.replace(f.name, p)

def recent_session_write():
    now = time.time()
    for dp, _, fs in os.walk(SESSIONS):
        for n in fs:
            if n.endswith(".jsonl") and now - os.path.getmtime(os.path.join(dp, n)) < 5:
                sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "stale-switches":
        check_kill_switch_staleness()
    elif cmd == "recent-session-write":
        recent_session_write()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)

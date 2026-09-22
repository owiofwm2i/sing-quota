#!/usr/bin/env python3
import argparse
import calendar
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

DIR = Path("/etc/sing-box")
STATE_DIR = Path("/var/lib/sing-quota")
CONFIG = DIR / "config.json"
QUOTAS = DIR / "quotas.json"
STATE = STATE_DIR / "quota-state.json"
LOCK = STATE_DIR / "quota.lock"
PROTO = Path("/app/stats.proto")
API = "sing-box:10085"
INTERVAL = 10
TZ = ZoneInfo("Asia/Shanghai")
SERVICE = "v2ray.core.app.stats.command.StatsService"


def load(path, default=None):
    if not path.exists():
        if default is not None:
            return default
        raise RuntimeError(f"missing {path}")
    return json.loads(path.read_text())


def save(path, value):
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def grpc(method, data):
    result = subprocess.run(
        [
            "grpcurl",
            "-plaintext",
            "-import-path",
            str(PROTO.parent),
            "-proto",
            PROTO.name,
            "-d",
            json.dumps(data),
            API,
            f"{SERVICE}/{method}",
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "V2Ray API unavailable")
    return json.loads(result.stdout or "{}")


def read_counters():
    response = grpc(
        "QueryStats",
        {"patterns": ["user>>>"], "reset": False, "regexp": False},
    )
    counters = {}
    for item in response.get("stat", []):
        match = re.fullmatch(
            r"user>>>(.+)>>>traffic>>>(uplink|downlink)", item.get("name", "")
        )
        if match:
            counters.setdefault(match.group(1), {"uplink": 0, "downlink": 0})
            counters[match.group(1)][match.group(2)] = int(item.get("value", 0))

    system = grpc("GetSysStats", {})
    uptime = int(system.get("Uptime", system.get("uptime", 0)))
    return counters, time.time() - uptime


def new_state():
    return {"epoch": None, "managed_rule": None, "users": {}}


def update_usage(quotas, state, counters, epoch):
    same_process = state["epoch"] is not None and abs(epoch - state["epoch"]) <= 3
    for name in list(state["users"]):
        if name not in quotas:
            del state["users"][name]

    for name in quotas:
        user = state["users"].setdefault(
            name,
            {
                "used": 0,
                "last_uplink": 0,
                "last_downlink": 0,
                "last_reset_period": datetime.now(TZ).strftime("%Y-%m"),
            },
        )
        current = counters.get(name, {"uplink": 0, "downlink": 0})
        delta = 0
        for direction in ("uplink", "downlink"):
            key = f"last_{direction}"
            value = current[direction]
            previous = user[key]
            delta += value - previous if same_process and value >= previous else value
            user[key] = value
        user["used"] += max(delta, 0)
    state["epoch"] = epoch


def reset_due(quotas, state, now):
    changed = False
    period = now.strftime("%Y-%m")
    last_day = calendar.monthrange(now.year, now.month)[1]
    for name, quota in quotas.items():
        day = int(quota.get("reset_day", 0))
        user = state["users"][name]
        if (
            day
            and now.day >= min(day, last_day)
            and user["last_reset_period"] != period
        ):
            user["used"] = 0
            user["last_reset_period"] = period
            changed = True
    return changed


def blocked_users(quotas, state):
    return sorted(
        name
        for name, quota in quotas.items()
        if float(quota.get("limit_gb", 0)) > 0
        and state["users"].get(name, {}).get("used", 0)
        >= float(quota["limit_gb"]) * 1024**3
    )


def apply_block_rule(state, blocked):
    config = load(CONFIG)
    original = json.dumps(config, sort_keys=True)
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    old_rule = state.get("managed_rule")
    if old_rule:
        rules[:] = [rule for rule in rules if rule != old_rule]

    new_rule = {"auth_user": blocked, "action": "reject"} if blocked else None
    if new_rule:
        rules.insert(0, new_rule)

    if new_rule == old_rule and json.dumps(config, sort_keys=True) == original:
        return False

    next_config = DIR / "config.next.json"
    save(next_config, config)
    check = subprocess.run(
        ["sing-box", "check", "-c", str(next_config)],
        capture_output=True,
        text=True,
    )
    if check.returncode:
        next_config.unlink(missing_ok=True)
        raise RuntimeError(check.stderr.strip() or "sing-box check failed")

    os.replace(next_config, CONFIG)
    os.kill(1, signal.SIGHUP)
    state["managed_rule"] = new_rule
    state["epoch"] = None
    for user in state["users"].values():
        user["last_uplink"] = 0
        user["last_downlink"] = 0
    return True


def tick():
    quotas = load(QUOTAS)
    state = load(STATE, new_state())
    counters, epoch = read_counters()
    update_usage(quotas, state, counters, epoch)
    reset_due(quotas, state, datetime.now(TZ))
    blocked = blocked_users(quotas, state)
    save(STATE, state)
    if apply_block_rule(state, blocked):
        save(STATE, state)
        print("blocked users:", ", ".join(blocked) or "none", flush=True)


def reload_sing_box():
    quotas = load(QUOTAS)
    state = load(STATE, new_state())
    counters, epoch = read_counters()
    update_usage(quotas, state, counters, epoch)
    save(STATE, state)

    check = subprocess.run(
        ["sing-box", "check", "-c", str(CONFIG)],
        capture_output=True,
        text=True,
    )
    if check.returncode:
        raise RuntimeError(check.stderr.strip() or "sing-box check failed")

    os.kill(1, signal.SIGHUP)
    state["epoch"] = None
    for user in state["users"].values():
        user["last_uplink"] = 0
        user["last_downlink"] = 0
    save(STATE, state)
    print("sing-box reloaded", flush=True)


def status():
    quotas = load(QUOTAS)
    state = load(STATE, new_state())
    print(f"{'USER':<20} {'USED':>12} {'LIMIT':>12} {'STATUS':>10}")
    blocked = set(blocked_users(quotas, state)) if state["users"] else set()
    for name, quota in sorted(quotas.items()):
        used = state["users"].get(name, {}).get("used", 0) / 1024**3
        limit = float(quota.get("limit_gb", 0))
        print(
            f"{name:<20} {used:>9.2f} GB "
            f"{('unlimited' if not limit else f'{limit:.2f} GB'):>12} "
            f"{('blocked' if name in blocked else 'active'):>10}"
        )


def reset_user(name):
    state = load(STATE, new_state())
    if name not in state["users"]:
        raise RuntimeError(f"unknown user: {name}")
    state["users"][name]["used"] = 0
    save(STATE, state)
    tick()


def main():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("watch", "once", "status", "reset", "reload"),
        nargs="?",
        default="watch",
    )
    parser.add_argument("user", nargs="?")
    args = parser.parse_args()

    if args.command == "status":
        status()
        return

    if args.command == "watch":
        while True:
            try:
                with LOCK.open("a+") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    tick()
            except Exception as error:
                print(error, file=sys.stderr, flush=True)
            time.sleep(INTERVAL)

    with LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.command == "reset":
            if not args.user:
                parser.error("reset requires USER")
            reset_user(args.user)
        elif args.command == "reload":
            reload_sing_box()
        else:
            tick()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local Android audit, reviewed reversible disable and exact-state restore.

No third-party dependencies. No uninstall, data clearing, deletion or HDC writes.
See references/adb-helper.md for human review and the normal UI workflow.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

VERSION = "0.1.1"
SCHEMA = 1
PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")
COMPONENT = re.compile(r"(android|[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/[A-Za-z_.$][A-Za-z0-9_.$]*\Z")
PROPERTIES = {
    "manufacturer": "ro.product.manufacturer", "brand": "ro.product.brand",
    "model": "ro.product.model", "device": "ro.product.device",
    "sdk": "ro.build.version.sdk", "android": "ro.build.version.release",
    "display": "ro.build.display.id", "fingerprint": "ro.build.fingerprint",
    "harmony": "hw_sc.build.platform.version",
}
PROTECTED = {
    "android", "com.android.systemui", "com.android.settings", "com.android.phone",
    "com.android.server.telecom", "com.android.contacts", "com.android.mms",
    "com.android.launcher", "com.android.launcher3", "com.android.camera",
    "com.android.camera2", "com.android.documentsui", "com.android.packageinstaller",
    "com.android.permissioncontroller", "com.android.vending", "com.google.android.gms",
    "com.google.android.gsf", "com.google.android.packageinstaller",
    "com.google.android.permissioncontroller", "com.google.android.webview",
    "com.android.webview", "com.huawei.android.launcher", "com.huawei.filemanager",
    "com.huawei.hidisk", "com.huawei.camera", "com.android.gallery3d",
    "com.baidu.input_huawei", "com.huawei.ohos.inputmethod",
    "com.huawei.android.thememanager", "com.huawei.systemmanager", "com.huawei.hwouc",
    "com.huawei.hwid", "com.huawei.hms", "com.huawei.ims", "com.huawei.appmarket",
    "com.huawei.android.hwouc", "com.android.updater", "com.google.android.configupdater",
    "com.huawei.fastapp", "com.huawei.browser", "com.huawei.browser.fa", "com.android.browser",
}
PROTECTED_PREFIXES = ("com.android.providers.", "com.google.android.providers.")


class GuardError(Exception):
    """A bounded stop requiring inspection, never a bypass or blind retry."""


@contextmanager
def session_lock(folder):
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise GuardError("Use an existing, ordinary private session directory.")
    lock = folder / ".operation.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise GuardError("Session is locked. Inspect any running/interrupted operation; do not blindly remove the lock.") from exc
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))
        yield
    finally:
        # Only this invocation's own ordinary lock file, never a device/user-data path.
        if lock.is_file() and not lock.is_symlink():
            lock.unlink()


def session_locked(index):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            folder = args[index] if len(args) > index else kwargs["folder"]
            with session_lock(folder):
                return function(*args, **kwargs)
        return wrapped
    return decorate


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_json(path, value):
    """Atomic checkpoint written before a device mutation; no recursive deletion."""
    path = Path(path)
    if path.is_symlink():
        raise GuardError("Refusing a symlink as a session file.")
    temp = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    with temp.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise GuardError("Missing, oversized or symlinked session file.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise GuardError("Session/profile JSON must be an object.")
        return value
    except (ValueError, UnicodeError) as exc:
        raise GuardError("Invalid UTF-8 JSON session file.") from exc


def package_name(value):
    if not isinstance(value, str) or (value != "android" and not PACKAGE.fullmatch(value)):
        raise GuardError("Invalid package name; components and shell syntax are not allowed.")
    return value


def protected(value, extra=()):
    return value in PROTECTED or value in extra or value.startswith(PROTECTED_PREFIXES)


def component_packages(value, optional=False, multiple=False):
    if optional and value == "null":
        return set()
    parts = value.split(":") if multiple else [value]
    result = set()
    for part in parts:
        match = COMPONENT.fullmatch(part)
        if not match:
            raise GuardError("Cannot establish a protected component/service state; use normal UI inspection.")
        result.add(match[1])
    return result


def profiles():
    raw = read_json(Path(__file__).resolve().parents[1] / "references" / "profiles.json")
    if raw.get("schema") != SCHEMA:
        raise GuardError("Unsupported profile schema.")
    return raw["profiles"]


def matching_profile(props):
    found = [p for p in profiles() if all(props.get(k) == v for k, v in p["match"].items())]
    if len(found) > 1:
        raise GuardError("Ambiguous device profiles.")
    return found[0] if found else None


def parse_devices(output):
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("List of devices", "* daemon", "adb server")):
            continue
        fields = line.split()
        if len(fields) >= 2:
            rows.append(fields)
    if len(rows) != 1:
        raise GuardError("Connect exactly one USB phone; disconnect other devices/emulators.")
    serial, state, *details = rows[0]
    if state != "device":
        raise GuardError("Phone is offline, unauthorized or inaccessible; confirm on the phone.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", serial) or serial.startswith("emulator-"):
        raise GuardError("Only an authorized physical USB phone is supported.")
    # Windows ADB may omit usb: metadata. connect() verifies the transport using -d.
    return serial


def parse_packages(output):
    result = set()
    for line in output.splitlines():
        if line.startswith("package:"):
            result.add(package_name(line[8:].strip()))
    if not result:
        raise GuardError("No Android package list; use the platform/UI route instead.")
    return sorted(result)


def parse_state(output):
    row = re.search(r"^\s*User 0:\s*(.*)$", output, re.MULTILINE)
    if not row or not re.search(r"\binstalled=true\b", row[1]):
        raise GuardError("Package is missing or its user state cannot be read.")
    if re.search(r"\b(hidden|suspended)=true\b", row[1]):
        raise GuardError("Package has hidden/suspended state; inspect manually.")
    enabled = re.search(r"\benabled=([0-4])\b", row[1])
    if not enabled:
        raise GuardError("Unknown enabled-state format; no device change permitted.")
    return int(enabled[1])


class Adb:
    def __init__(self, executable="adb", runner=subprocess.run):
        self.executable = str(executable)
        self.runner = runner
        self.serial = None

    def run(self, *args, usb=False):
        target = ["-d"] if usb else (["-s", self.serial] if self.serial else [])
        prefix = [self.executable] + target
        try:
            result = self.runner(prefix + list(args), capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=25, shell=False)
        except FileNotFoundError as exc:
            raise GuardError("ADB not found. Install official Android Platform Tools.") from exc
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise GuardError("ADB timed out or connection failed; inspect before retrying.") from exc
        if result.returncode:
            # Raw diagnostics may contain a serial or private device details.
            raise GuardError("ADB command rejected. No escalation or automatic retry.")
        return result.stdout.strip()

    def connect(self):
        self.serial = None
        self.serial = parse_devices(self.run("devices", "-l"))
        if self.run("get-serialno", usb=True) != self.serial:
            raise GuardError("Cannot confirm this device is the unique physical USB phone.")
        if self.run("get-state") != "device":
            raise GuardError("USB device state changed.")
        return self

    def shell(self, *args):
        # No user-provided raw shell strings: fixed commands and validated tokens only.
        return self.run("shell", *args)

    def properties(self):
        props = {key: self.shell("getprop", value) for key, value in PROPERTIES.items()}
        try:
            sdk = int(props["sdk"])
        except ValueError as exc:
            raise GuardError("Not a supported main-system Android environment; inspect HarmonyOS/UI.") from exc
        if sdk < 26 or not props["fingerprint"]:
            raise GuardError("Helper requires Android API 26+ and a readable build fingerprint.")
        if self.shell("am", "get-current-user") != "0":
            raise GuardError("Helper only supports the foreground primary user 0.")
        return props

    def environment(self):
        users = self.shell("pm", "list", "users")
        ids = re.findall(r"UserInfo\{(\d+):", users)
        if not ids or "0" not in ids:
            raise GuardError("Cannot establish the user/profile scope.")
        policy = self.shell("dumpsys", "device_policy")
        if (not re.search(r"(?:Current Device Policy Manager state|Device Policy Manager)", policy)
                or re.search(r"(?:Exception|Error:|Can't find service|not found|Permission Denial)", policy, re.I)):
            raise GuardError("Cannot inspect device management status.")
        managed = bool(re.search(r"(?:Device Owner:|Profile Owner \(|mDeviceOwner=ComponentInfo)", policy))
        return {"user_count": len(ids), "management_detected": managed}

    def dynamic_protected(self):
        values = [self.shell("settings", "get", "secure", key) for key in
                  ("default_input_method", "enabled_accessibility_services", "enabled_notification_listeners")]
        home = self.shell("cmd", "package", "resolve-activity", "--brief", "--components", "--user", "0",
                          "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME")
        found = component_packages(home) | component_packages(values[0])
        for value in values[1:]:
            found |= component_packages(value, optional=True, multiple=True)
        return sorted(found)

    def state(self, pkg):
        return parse_state(self.shell("dumpsys", "package", package_name(pkg)))


def bind(adb, props, salt):
    return digest({"salt": salt, "usb_id": adb.serial, "fingerprint": props["fingerprint"]})


def audit(adb, folder):
    folder = Path(folder)
    if folder.exists():
        raise GuardError("Choose a new private output folder; existing sessions are never overwritten.")
    adb.connect()
    props = adb.properties()
    environment = adb.environment()
    extra = adb.dynamic_protected()
    packages = parse_packages(adb.shell("pm", "list", "packages", "--user", "0"))
    profile = matching_profile(props)
    candidates = {}
    if profile:
        for pkg, info in profile["candidates"].items():
            package_name(pkg)
            if pkg in packages and not protected(pkg, extra):
                candidates[pkg] = dict(info, before=adb.state(pkg))
    salt = secrets.token_hex(16)
    report = {"schema": SCHEMA, "version": VERSION, "created_at": now(),
              "route": "android-adb", "properties": props, "environment": environment,
              "salt": salt, "binding": bind(adb, props, salt), "packages": packages,
              "protected": extra, "profile_id": profile["id"] if profile else None,
              "profile_evidence": profile["evidence"] if profile else None,
              "candidates": candidates,
              "scope_warning": "Confirm main Android system, not a container; review management in UI."}
    folder.mkdir(parents=True, exist_ok=False)
    write_json(folder / "audit.json", report)
    return {"audit": str(folder / "audit.json"), "package_count": len(packages),
            "candidate_count": len(candidates), "profile_id": report["profile_id"],
            "environment": environment, "device_changes": 0}


def load_audit(folder):
    report = read_json(Path(folder) / "audit.json")
    if report.get("schema") != SCHEMA or report.get("route") != "android-adb":
        raise GuardError("Unsupported audit schema or route.")
    profile = matching_profile(report["properties"])
    if not profile or report["profile_id"] != profile["id"]:
        raise GuardError("No exact firmware profile for automatic changes. Use normal UI controls.")
    if report["environment"] != {"user_count": 1, "management_detected": False}:
        raise GuardError("Managed or multi-user devices are read-only in this helper.")
    return report, profile


def validate_actions(report, profile, actions):
    if not isinstance(actions, list) or not actions or len(actions) > len(profile["candidates"]):
        raise GuardError("An explicit, nonempty candidate selection is required.")
    seen = set()
    for item in actions:
        pkg = package_name(item.get("package"))
        if pkg in seen or protected(pkg, report["protected"]) or pkg not in profile["candidates"]:
            raise GuardError("Duplicate, protected or unsupported package in plan.")
        seen.add(pkg)
        if (pkg not in report["packages"] or pkg not in report["candidates"]
                or type(item.get("before")) is not int or item["before"] not in (0, 1)
                or item["before"] != report["candidates"][pkg]["before"]
                or item.get("operation") != "disable-user"):
            raise GuardError("Plan does not match the original installed/enabled package state.")


@session_locked(0)
def make_plan(folder, packages, reason, context):
    folder = Path(folder)
    if (folder / "plan.json").exists():
        raise GuardError("Plan exists. Create a fresh audit session for a changed plan.")
    report, profile = load_audit(folder)
    if not reason.strip() or len(context.strip()) < 12:
        raise GuardError("Record purpose and UI review of main-system/management status.")
    actions = []
    for pkg in packages:
        package_name(pkg)
        if pkg not in report["candidates"]:
            raise GuardError("Selected package is not an installed candidate in the matching profile.")
        actions.append({"package": pkg, "operation": "disable-user",
                        "before": report["candidates"][pkg]["before"],
                        **profile["candidates"][pkg]})
    validate_actions(report, profile, actions)
    plan = {"schema": SCHEMA, "created_at": now(), "audit_digest": digest(report),
            "binding": report["binding"], "profile_id": profile["id"],
            "profile_match": profile["match"], "profile_evidence": profile["evidence"],
            "reason": reason, "ui_context_review": context, "actions": actions}
    plan["digest"] = digest(plan)
    write_json(folder / "plan.json", plan)
    return plan


def load_plan(folder):
    report, profile = load_audit(folder)
    plan = read_json(Path(folder) / "plan.json")
    plain = {k: v for k, v in plan.items() if k != "digest"}
    if (plan.get("schema") != SCHEMA or plan.get("digest") != digest(plain)
            or plan.get("audit_digest") != digest(report)
            or plan.get("binding") != report["binding"] or plan.get("profile_id") != profile["id"]):
        raise GuardError("Plan/audit integrity mismatch. Do not edit a reviewed plan.")
    validate_actions(report, profile, plan["actions"])
    return report, plan


def live_check(adb, report):
    adb.connect()
    props = adb.properties()
    if props != report["properties"] or bind(adb, props, report["salt"]) != report["binding"]:
        raise GuardError("Different phone or firmware; no changes or automatic restore permitted.")
    if adb.environment() != {"user_count": 1, "management_detected": False}:
        raise GuardError("User/profile/management state changed; stop for inspection.")
    return adb.dynamic_protected()


def require_approval(plan, approval):
    if approval != plan["digest"]:
        raise GuardError("Pass the exact reviewed plan digest; this does not replace human authorization.")


def load_journal(folder, plan):
    journal = read_json(Path(folder) / "journal.json")
    expected = [(i["package"], i["before"]) for i in plan["actions"]]
    actual = [(i.get("package"), i.get("before")) for i in journal.get("entries", [])]
    if journal.get("schema") != SCHEMA or journal.get("plan_digest") != plan["digest"] or actual != expected:
        raise GuardError("Recovery journal does not match the reviewed plan.")
    statuses = {"not_started", "intent", "applied", "uncertain", "restored"}
    if any(i.get("status") not in statuses for i in journal["entries"]):
        raise GuardError("Unknown recovery entry status.")
    return journal


@session_locked(1)
def apply(adb, folder, approval):
    folder = Path(folder)
    report, plan = load_plan(folder)
    require_approval(plan, approval)
    try:
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(report["created_at"])
    except (ValueError, TypeError) as exc:
        raise GuardError("Invalid audit timestamp.") from exc
    if not dt.timedelta(0) <= age <= dt.timedelta(hours=24):
        raise GuardError("Audit is stale; create a fresh audit and plan before applying.")
    if (folder / "journal.json").exists():
        raise GuardError("Execution journal exists. Verify or restore instead of replaying.")
    extra = live_check(adb, report)
    # Preflight all targets before any write.
    for item in plan["actions"]:
        if protected(item["package"], extra) or adb.state(item["package"]) != item["before"]:
            raise GuardError("Target protection/state changed since audit; no changes made.")
    journal = {"schema": SCHEMA, "version": VERSION, "plan_digest": plan["digest"],
               "started_at": now(), "stage": "applying", "entries": [
                   {"package": i["package"], "before": i["before"], "status": "not_started"}
                   for i in plan["actions"]]}
    write_json(folder / "journal.json", journal)
    for entry in journal["entries"]:
        entry["status"] = "intent"
        write_json(folder / "journal.json", journal)
        try:
            adb.shell("pm", "disable-user", "--user", "0", entry["package"])
            if adb.state(entry["package"]) != 3:
                raise GuardError("Disable did not persist; inspect the normal settings UI.")
        except GuardError:
            entry["status"] = "uncertain"
            journal["stage"] = "interrupted"
            write_json(folder / "journal.json", journal)
            raise GuardError("Execution stopped. Preserve this session; inspect and restore, not apply again.")
        entry["status"] = "applied"
        write_json(folder / "journal.json", journal)
    journal["stage"] = "applied"
    write_json(folder / "journal.json", journal)
    return {"stage": "applied", "disabled": len(journal["entries"]), "data_clearing_commands": 0}


@session_locked(1)
def restore(adb, folder, approval):
    folder = Path(folder)
    report, plan = load_plan(folder)
    require_approval(plan, approval)
    journal = load_journal(folder, plan)
    extra = live_check(adb, report)
    for entry in reversed(journal["entries"]):
        if entry["status"] == "not_started":
            continue
        if entry["status"] == "restored":
            if adb.state(entry["package"]) != entry["before"]:
                raise GuardError("A previously restored package changed; inspect manually.")
            continue
        if protected(entry["package"], extra):
            raise GuardError("Target became protected; inspect recovery manually.")
        current = adb.state(entry["package"])
        if current == entry["before"]:
            entry["status"] = "restored"
            write_json(folder / "journal.json", journal)
            continue
        if current != 3:
            raise GuardError("External package-state conflict; no blind restore.")
        journal["stage"] = "restoring"
        write_json(folder / "journal.json", journal)
        verb = "default-state" if entry["before"] == 0 else "enable"
        adb.shell("pm", verb, "--user", "0", entry["package"])
        if adb.state(entry["package"]) != entry["before"]:
            raise GuardError("Restore read-back failed; preserve the recovery journal.")
        entry["status"] = "restored"
        write_json(folder / "journal.json", journal)
    journal["stage"] = "restored"
    write_json(folder / "journal.json", journal)
    return {"stage": "restored", "entries": len(journal["entries"])}


@session_locked(1)
def verify(adb, folder):
    folder = Path(folder)
    report, plan = load_plan(folder)
    journal = load_journal(folder, plan)
    live_check(adb, report)
    rows = []
    for entry in journal["entries"]:
        actual = adb.state(entry["package"])
        expected = (entry["before"] if entry["status"] in ("restored", "not_started") else
                    3 if entry["status"] == "applied" else None)
        rows.append({"package": entry["package"], "expected": expected, "actual": actual,
                     "verified": expected is not None and actual == expected})
    current_packages = set(parse_packages(adb.shell("pm", "list", "packages", "--user", "0")))
    missing = sorted(set(report["packages"]) - current_packages)
    result = {"checked_at": now(), "stage": journal["stage"], "entries": rows,
              "all_expected_states": all(i["verified"] for i in rows),
              "installed_packages_preserved": not missing, "missing_packages": missing,
              "scope": "Package state and baseline installation presence only; missing packages are not proof of cause. Ads, UI, data contents, updater behavior and reboot persistence need separate checks."}
    write_json(folder / "verification.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "plan", "apply", "restore", "verify"):
        sub = subs.add_parser(name)
        if name == "audit":
            sub.add_argument("--out", required=True, help="New private session folder outside this repository")
        else:
            sub.add_argument("--session", required=True)
        if name != "plan":
            sub.add_argument("--adb", default="adb", help="Trusted official adb executable")
        if name == "plan":
            sub.add_argument("--package", action="append", required=True)
            sub.add_argument("--reason", required=True)
            sub.add_argument("--context-review", required=True,
                             help="UI evidence of main-system Android and no device management")
        if name in ("apply", "restore"):
            sub.add_argument("--approved-plan", required=True, help="Exact digest of the human-reviewed plan")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = make_plan(args.session, args.package, args.reason, args.context_review)
        else:
            adb = Adb(args.adb)
            if args.command == "audit":
                result = audit(adb, args.out)
            elif args.command == "apply":
                result = apply(adb, args.session, args.approved_plan)
            elif args.command == "restore":
                result = restore(adb, args.session, args.approved_plan)
            else:
                result = verify(adb, args.session)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.command != "verify" or (result["all_expected_states"] and result["installed_packages_preserved"]) else 2
    except (GuardError, OSError, KeyError, TypeError, ValueError) as exc:
        message = str(exc) if isinstance(exc, GuardError) else "Invalid session data or local I/O failure; inspect private files."
        print(json.dumps({"stopped": True, "reason": message}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

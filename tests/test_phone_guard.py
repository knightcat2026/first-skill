"""Synthetic transport tests. These tests never execute adb or contact a phone."""
from __future__ import annotations

import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "phone-clean-guard" / "scripts" / "phone_guard.py"
SPEC = importlib.util.spec_from_file_location("phone_guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
FIRST = "com.huawei.recsys"
SECOND = "com.huawei.ohos.suggestion"
CONTEXT = "Settings UI checked: this is primary Android, no work profile or device management."


class FakeTransport:
    """Answers the actual argv accepted by Adb, including pre-write recovery checks."""

    def __init__(self):
        self.serial = "SYNTHETIC-USB-01"
        self.usb_serial = None
        self.listing = None
        self.props = dict(guard.profiles()[0]["match"], android="10", fingerprint="synthetic/build/fingerprint")
        self.users = "Users:\n  UserInfo{0:Owner:13} running"
        self.policy = "Current Device Policy Manager state:\n  no owners"
        self.current_user = "0"
        self.keyboard = "org.example.keyboard/.InputService"
        self.home = "org.example.launcher/.Home"
        self.accessibility = "null"
        self.listeners = "null"
        self.states = {FIRST: 0, SECOND: 1, "org.example.notes": 0}
        # Inert synthetic markers: no actual personal files or phone storage are read.
        self.user_data = {"photo": b"synthetic photo bytes", "notes": b"synthetic private notes"}
        self.apk_files = {"/sdcard/Download/existing.apk": b"synthetic existing installer"}
        self.update_preferences = {"system_auto_update": True, "app_auto_update": "wifi_only"}
        self.calls = []
        self.writes = []
        self.failure_package = None
        self.failure_mode = "rejected"
        self.session = None
        self.before_write_statuses = []
        self.hidden = set()
        self.absent = set()

    def __call__(self, argv, **options):
        if options.get("shell") is not False:
            raise AssertionError("Transport must never invoke a host shell")
        self.calls.append(list(argv))
        args = argv[1:]
        if args[:1] == ["-s"]:
            if args[1] != self.serial:
                raise AssertionError("Wrong selected serial")
            args = args[2:]
        if args == ["-d", "get-serialno"]:
            return subprocess.CompletedProcess(argv, 0, self.usb_serial or self.serial, "")
        if args == ["devices", "-l"]:
            output = self.listing or f"List of devices attached\n{self.serial} device usb:1-2 product:synthetic transport_id:1\n"
        elif args == ["get-state"]:
            output = "device"
        elif args[:2] == ["shell", "getprop"]:
            reverse = {v: k for k, v in guard.PROPERTIES.items()}
            output = self.props[reverse[args[2]]]
        elif args == ["shell", "am", "get-current-user"]:
            output = self.current_user
        elif args == ["shell", "pm", "list", "users"]:
            output = self.users
        elif args == ["shell", "dumpsys", "device_policy"]:
            output = self.policy
        elif args[:4] == ["shell", "settings", "get", "secure"]:
            output = {"default_input_method": self.keyboard,
                      "enabled_accessibility_services": self.accessibility,
                      "enabled_notification_listeners": self.listeners}[args[4]]
        elif args[:4] == ["shell", "cmd", "package", "resolve-activity"]:
            output = self.home
        elif args == ["shell", "pm", "list", "packages", "--user", "0"]:
            output = "\n".join("package:" + key for key in self.states)
        elif args[:3] == ["shell", "dumpsys", "package"]:
            package = args[3]
            if package in self.absent:
                output = "Unable to find package"
            else:
                hidden = str(package in self.hidden).lower()
                output = (f"Package [{package}]:\n  User 0: installed=true hidden={hidden} "
                          f"suspended=false enabled={self.states[package]} stopped=false\n")
        elif args[:2] == ["shell", "pm"] and args[2] in ("disable-user", "enable", "default-state"):
            if args[3:5] != ["--user", "0"] or len(args) != 6:
                raise AssertionError("Unexpected mutation scope")
            package = args[5]
            if self.session is not None:
                journal = guard.read_json(self.session / "journal.json")
                status = next(i["status"] for i in journal["entries"] if i["package"] == package)
                self.before_write_statuses.append((args[2], package, status))
                if args[2] == "disable-user" and status != "intent":
                    raise AssertionError("Device write happened before durable intent")
            self.writes.append((args[2], package))
            if args[2] == "disable-user" and package == self.failure_package:
                if self.failure_mode == "timeout-after-write":
                    self.states[package] = 3
                    raise subprocess.TimeoutExpired(argv, 25)
                if self.failure_mode == "silent-reject":
                    return subprocess.CompletedProcess(argv, 0, "SecurityException", "")
                return subprocess.CompletedProcess(argv, 1, "", "synthetic rejection")
            self.states[package] = {"disable-user": 3, "enable": 1, "default-state": 0}[args[2]]
            output = "Package new state accepted"
        else:
            raise AssertionError("Unexpected command: " + repr(args))
        return subprocess.CompletedProcess(argv, 0, output, "")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phone-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "私密 会话"
        self.transport = FakeTransport()
        self.adb = guard.Adb("official tools/adb", runner=self.transport)
        self.transport.session = self.folder

    def audited(self):
        return guard.audit(self.adb, self.folder)

    def planned(self, *packages):
        self.audited()
        return guard.make_plan(self.folder, list(packages or (FIRST,)), "Close recommendation entry", CONTEXT)

    def assert_no_writes(self):
        self.assertEqual(self.transport.writes, [])

    def assert_invalid_dynamic_states_stop_audit_and_apply(self, keys, values):
        """Check both initial discovery and revalidation of a reviewed session."""
        counter = 0
        for key in keys:
            for value in values:
                for phase in ("audit", "apply"):
                    counter += 1
                    with self.subTest(key=key, value=value, phase=phase):
                        self.folder = Path(self.temp.name) / f"state-case-{counter}"
                        self.transport = FakeTransport()
                        self.transport.session = self.folder
                        self.adb = guard.Adb("official tools/adb", runner=self.transport)
                        if phase == "apply":
                            plan = self.planned()
                        setattr(self.transport, key, value)
                        with self.assertRaises(guard.GuardError):
                            if phase == "audit":
                                self.audited()
                            else:
                                guard.apply(self.adb, self.folder, plan["digest"])
                        self.assert_no_writes()
                        self.assertFalse((self.folder / "journal.json").exists())

    def test_audit_is_read_only_and_does_not_publish_serial_or_full_policy(self):
        result = self.audited()
        self.assertEqual(result["device_changes"], 0)
        self.assertEqual(result["candidate_count"], 2)
        self.assert_no_writes()
        serialized = (self.folder / "audit.json").read_text(encoding="utf-8")
        self.assertNotIn(self.transport.serial, serialized)
        self.assertNotIn(self.transport.policy, serialized)
        self.assertIn("私密 会话", result["audit"])

    def test_default_and_explicit_enabled_restore_exact_original_state(self):
        plan = self.planned(FIRST, SECOND)
        guard.apply(self.adb, self.folder, plan["digest"])
        self.assertEqual([self.transport.states[FIRST], self.transport.states[SECOND]], [3, 3])
        self.assertTrue(guard.verify(self.adb, self.folder)["all_expected_states"])
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual([self.transport.states[FIRST], self.transport.states[SECOND]], [0, 1])
        self.assertEqual(self.transport.writes[-2:], [("enable", SECOND), ("default-state", FIRST)])
        self.assertTrue(guard.verify(self.adb, self.folder)["all_expected_states"])
        before = list(self.transport.writes)
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.writes, before)

    def test_lifecycle_preserves_installed_apps_apks_user_data_and_update_preferences(self):
        untouched = ("com.huawei.android.hwouc", "com.huawei.appmarket",
                     "com.huawei.fastapp", "com.huawei.browser", "org.example.notes")
        self.transport.states.update({pkg: 0 for pkg in untouched})
        original_packages = set(self.transport.states)
        original_data = copy.deepcopy(self.transport.user_data)
        original_apks = copy.deepcopy(self.transport.apk_files)
        original_updates = copy.deepcopy(self.transport.update_preferences)
        plan = self.planned(FIRST, SECOND)
        guard.apply(self.adb, self.folder, plan["digest"])
        verified = guard.verify(self.adb, self.folder)
        self.assertTrue(verified["all_expected_states"])
        self.assertTrue(verified["installed_packages_preserved"])
        self.assertEqual(verified["missing_packages"], [])
        self.assertEqual(set(self.transport.states), original_packages)
        self.assertTrue(all(self.transport.states[pkg] == 0 for pkg in untouched))
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertTrue(guard.verify(self.adb, self.folder)["installed_packages_preserved"])
        self.assertEqual(set(self.transport.states), original_packages)
        self.assertEqual(self.transport.user_data, original_data)
        self.assertEqual(self.transport.apk_files, original_apks)
        self.assertEqual(self.transport.update_preferences, original_updates)
        self.assertEqual(self.transport.writes, [("disable-user", FIRST), ("disable-user", SECOND),
                                                 ("enable", SECOND), ("default-state", FIRST)])
        for argv in self.transport.calls:
            self.assertFalse(any(token in {"uninstall", "clear", "rm", "reboot", "install", "put", "set"}
                                 for token in argv))

    def test_missing_baseline_app_is_reported_even_when_target_states_pass(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.states.pop("org.example.notes")
        result = guard.verify(self.adb, self.folder)
        self.assertTrue(result["all_expected_states"])
        self.assertFalse(result["installed_packages_preserved"])
        self.assertEqual(result["missing_packages"], ["org.example.notes"])

    def test_verify_cli_fails_on_missing_baseline_app_without_real_adb(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.states.pop("org.example.notes")
        output = io.StringIO()
        with mock.patch.object(guard, "Adb", return_value=self.adb), contextlib.redirect_stdout(output):
            code = guard.main(["verify", "--adb", "synthetic-only", "--session", str(self.folder)])
        self.assertEqual(code, 2)
        result = json.loads(output.getvalue())
        self.assertTrue(result["all_expected_states"])
        self.assertFalse(result["installed_packages_preserved"])
        self.assertEqual(result["missing_packages"], ["org.example.notes"])

    def test_newly_installed_app_is_preserved_and_not_a_baseline_failure(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.states["org.example.newapp"] = 0
        original_writes = list(self.transport.writes)
        result = guard.verify(self.adb, self.folder)
        self.assertTrue(result["all_expected_states"])
        self.assertTrue(result["installed_packages_preserved"])
        self.assertEqual(result["missing_packages"], [])
        self.assertEqual(self.transport.states["org.example.newapp"], 0)
        self.assertEqual(self.transport.writes, original_writes)

    def test_update_channels_browser_and_fastapp_remain_protected_in_future_profile(self):
        profile = copy.deepcopy(guard.profiles()[0])
        protected_packages = ("com.huawei.hwouc", "com.huawei.android.hwouc", "com.android.updater",
                              "com.huawei.appmarket", "com.huawei.fastapp", "com.huawei.browser",
                              "com.android.browser")
        for pkg in protected_packages:
            self.transport.states[pkg] = 0
            profile["candidates"][pkg] = {"purpose": "synthetic mistaken candidate", "impact": "unknown"}
        with mock.patch.object(guard, "profiles", return_value=[profile]):
            self.audited()
            report = guard.read_json(self.folder / "audit.json")
            for pkg in protected_packages:
                with self.subTest(package=pkg):
                    self.assertIn(pkg, report["packages"])
                    self.assertNotIn(pkg, report["candidates"])
                    with self.assertRaises(guard.GuardError):
                        guard.make_plan(self.folder, [pkg], "Close promotional entry", CONTEXT)
        self.assert_no_writes()

    def test_wrong_phone_or_firmware_stops_before_writes(self):
        plan = self.planned()
        for kind in ("phone", "firmware"):
            with self.subTest(kind=kind):
                original_serial = self.transport.serial
                original_fp = self.transport.props["fingerprint"]
                if kind == "phone":
                    self.transport.serial = "SYNTHETIC-OTHER-PHONE"
                else:
                    self.transport.props["fingerprint"] = "other/firmware"
                with self.assertRaises(guard.GuardError):
                    guard.apply(self.adb, self.folder, plan["digest"])
                self.assert_no_writes()
                self.transport.serial = original_serial
                self.transport.props["fingerprint"] = original_fp

    def test_multiple_unauthorized_offline_emulator_network_are_rejected(self):
        cases = ["List of devices attached\n", "A device usb:1\nB device usb:2",
                 "A unauthorized usb:1", "A offline usb:1", "emulator-5554 device usb:1",
                 "192.0.2.1:5555 device product:synthetic"]
        for listing in cases:
            with self.subTest(listing=listing), self.assertRaises(guard.GuardError):
                guard.parse_devices(listing)

    def test_windows_usb_listing_without_usb_metadata_is_validated_by_d_selector(self):
        self.transport.listing = "List of devices attached\nSYNTHETIC-USB-01 device product:synthetic transport_id:1"
        self.audited()
        self.assertIn(["official tools/adb", "-d", "get-serialno"], self.transport.calls)
        self.assert_no_writes()

    def test_usb_selector_must_match_selected_phone(self):
        self.transport.usb_serial = "SYNTHETIC-OTHER-USB"
        with self.assertRaises(guard.GuardError):
            self.audited()
        self.assert_no_writes()

    def test_no_exact_profile_allows_audit_but_not_plan(self):
        self.transport.props["display"] = "different firmware"
        result = self.audited()
        self.assertIsNone(result["profile_id"])
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_keyboard_launcher_accessibility_and_notification_listener_are_protected(self):
        for key in ("keyboard", "home", "accessibility", "listeners"):
            with self.subTest(key=key):
                self.folder = Path(self.temp.name) / key
                setattr(self.transport, key, FIRST + "/.Service")
                self.audited()
                report = guard.read_json(self.folder / "audit.json")
                self.assertNotIn(FIRST, report["candidates"])
                with self.assertRaises(guard.GuardError):
                    guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
                setattr(self.transport, key, {"keyboard": "org.example.keyboard/.Ime",
                                             "home": "org.example.launcher/.Home"}.get(key, "null"))
        self.assert_no_writes()

    def test_dynamic_protection_changed_after_plan_prevents_all_writes(self):
        plan = self.planned(FIRST, SECOND)
        self.transport.accessibility = SECOND + "/.Accessibility"
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assert_no_writes()

    def test_empty_dynamic_component_outputs_fail_closed_at_audit_and_live_check(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("keyboard", "home", "accessibility", "listeners"), ("", " "))

    def test_dynamic_command_error_outputs_with_slashes_fail_closed(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("keyboard", "home", "accessibility", "listeners"),
            ("SecurityException: org.example.service/.Service", "Permission Denial: /data/system/state"))

    def test_required_components_reject_null_and_multiple_components(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("keyboard", "home"), ("null", "org.example.first/.Service:org.example.second/.Other"))

    def test_optional_service_lists_reject_mixed_null_and_empty_segments(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("accessibility", "listeners"),
            ("null:org.example.service/.Service", ":org.example.service/.Service",
             "org.example.service/.Service:", "org.example.first/.Service::org.example.second/.Other"))

    def test_component_syntax_and_arbitrary_text_fail_closed(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("keyboard", "home", "accessibility", "listeners"),
            ("org.example.service", "org.example.service/", "org.example.service/.Service;reboot", "unavailable"))

    def test_multiline_component_resolver_outputs_fail_closed(self):
        self.assert_invalid_dynamic_states_stop_audit_and_apply(
            ("keyboard", "home", "accessibility", "listeners"),
            ("org.example.first/.Service\norg.example.second/.Other", "Warning: resolver error\norg.example.service/.Service"))

    def test_legal_multiple_services_are_protected_in_audit_and_live_check(self):
        self.transport.accessibility = "org.example.reader/.Reader:org.example.assist/org.example.assist.FullService"
        self.transport.listeners = "org.example.wear/.Listener:org.example.watch/.Outer$Inner"
        self.audited()
        report = guard.read_json(self.folder / "audit.json")
        for package in ("org.example.reader", "org.example.assist", "org.example.wear", "org.example.watch"):
            self.assertIn(package, report["protected"])
        plan = guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        self.transport.listeners += ":" + FIRST + "/.NewListener"
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assert_no_writes()

    def test_android_release_mismatch_is_not_a_profile_match_even_with_same_sdk(self):
        self.transport.props["android"] = "14"
        self.assertEqual(self.transport.props["sdk"], "29")
        result = self.audited()
        self.assertIsNone(result["profile_id"])
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_multiuser_and_managed_audits_cannot_be_planned(self):
        for kind in ("work", "managed"):
            with self.subTest(kind=kind):
                self.folder = Path(self.temp.name) / kind
                self.transport.users = "UserInfo{0:Owner:13}" + ("\nUserInfo{10:Work:30}" if kind == "work" else "")
                self.transport.policy = "Current Device Policy Manager state:\n" + ("Device Owner: admin=ComponentInfo{org.example.owner/.Admin}" if kind == "managed" else "no owners")
                self.audited()
                with self.assertRaises(guard.GuardError):
                    guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_foreground_secondary_user_stops_audit(self):
        self.transport.current_user = "10"
        with self.assertRaises(guard.GuardError):
            self.audited()
        self.assertFalse(self.folder.exists())
        self.assert_no_writes()

    def test_unknown_or_rejected_policy_output_stops_audit_even_with_known_header(self):
        for policy in ("", "unrecognized management response", "Can't find service: device_policy",
                       "Current Device Policy Manager state:\nSecurityException: blocked",
                       "Device Policy Manager\nError: cannot inspect",
                       "Current Device Policy Manager state:\nPermission Denial",
                       "Device Policy Manager service not found"):
            with self.subTest(policy=policy):
                self.transport.policy = policy
                with self.assertRaises(guard.GuardError):
                    self.audited()
                self.assertFalse(self.folder.exists())
        self.assert_no_writes()

    def test_android_framework_is_audited_but_never_an_action_candidate(self):
        self.transport.states["android"] = 0
        self.audited()
        report = guard.read_json(self.folder / "audit.json")
        self.assertIn("android", report["packages"])
        self.assertNotIn("android", report["candidates"])
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, ["android"], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_wrong_approval_digest_prevents_connection_and_mutation(self):
        self.planned()
        before = len(self.transport.calls)
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, "0" * 64)
        self.assertEqual(len(self.transport.calls), before)
        self.assert_no_writes()

    def test_tampered_plan_and_audit_fail_integrity_check(self):
        plan = self.planned()
        for filename in ("plan.json", "audit.json"):
            with self.subTest(filename=filename):
                path = self.folder / filename
                original = guard.read_json(path)
                changed = dict(original, extra="unreviewed change")
                guard.write_json(path, changed)
                with self.assertRaises(guard.GuardError):
                    guard.apply(self.adb, self.folder, plan["digest"])
                guard.write_json(path, original)
        self.assert_no_writes()

    def test_later_target_changed_preflight_produces_zero_writes(self):
        plan = self.planned(FIRST, SECOND)
        self.transport.states[SECOND] = 3
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assert_no_writes()
        self.assertFalse((self.folder / "journal.json").exists())

    def test_interrupted_second_target_retains_write_ahead_journal_and_restores(self):
        plan = self.planned(FIRST, SECOND)
        self.transport.failure_package = SECOND
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        journal = guard.read_json(self.folder / "journal.json")
        self.assertEqual(journal["stage"], "interrupted")
        self.assertEqual([i["status"] for i in journal["entries"]], ["applied", "uncertain"])
        self.assertEqual(self.transport.states[FIRST], 3)
        self.assertEqual(self.transport.states[SECOND], 1)
        self.transport.failure_package = None
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual([self.transport.states[FIRST], self.transport.states[SECOND]], [0, 1])

    def test_timeout_after_device_write_is_recoverable(self):
        plan = self.planned()
        self.transport.failure_package = FIRST
        self.transport.failure_mode = "timeout-after-write"
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.states[FIRST], 3)
        self.assertEqual(guard.read_json(self.folder / "journal.json")["entries"][0]["status"], "uncertain")
        self.transport.failure_package = None
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.states[FIRST], 0)

    def test_silent_oem_security_rejection_fails_readback(self):
        plan = self.planned()
        self.transport.failure_package = FIRST
        self.transport.failure_mode = "silent-reject"
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.states[FIRST], 0)
        self.assertFalse(guard.verify(self.adb, self.folder)["all_expected_states"])

    def test_package_components_shell_syntax_and_unknown_packages_cannot_be_planned(self):
        self.audited()
        for package in (FIRST + "/.Service", FIRST + ";reboot", "$(reboot)", FIRST + "\nreboot",
                        "--user", "org.example.notes", "com.android.settings"):
            with self.subTest(package=package), self.assertRaises(guard.GuardError):
                guard.make_plan(self.folder, [package], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_duplicate_targets_and_initially_disabled_targets_are_rejected(self):
        self.audited()
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, [FIRST, FIRST], "Reason", CONTEXT)
        report = guard.read_json(self.folder / "audit.json")
        report["candidates"][FIRST]["before"] = 3
        guard.write_json(self.folder / "audit.json", report)
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        self.assert_no_writes()

    def test_repeat_apply_rejected_without_additional_writes(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        writes = list(self.transport.writes)
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assertEqual(writes, self.transport.writes)

    def test_restore_conflicting_external_state_is_not_overwritten(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.states[FIRST] = 2
        writes = list(self.transport.writes)
        with self.assertRaises(guard.GuardError):
            guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.writes, writes)

    def test_restore_fails_on_other_phone(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.serial = "SYNTHETIC-DIFFERENT"
        writes = list(self.transport.writes)
        with self.assertRaises(guard.GuardError):
            guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.writes, writes)

    def test_previously_restored_package_external_change_is_rejected(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        guard.restore(self.adb, self.folder, plan["digest"])
        self.transport.states[FIRST] = 3
        writes = list(self.transport.writes)
        with self.assertRaises(guard.GuardError):
            guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.writes, writes)
        self.assertFalse(guard.verify(self.adb, self.folder)["all_expected_states"])

    def test_restore_never_touches_not_started_targets(self):
        plan = self.planned(FIRST, SECOND)
        self.transport.failure_package = FIRST
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.transport.failure_package = None
        self.transport.states[SECOND] = 3
        guard.restore(self.adb, self.folder, plan["digest"])
        self.assertNotIn(("enable", SECOND), self.transport.writes)
        self.assertEqual(self.transport.states[SECOND], 3)
        self.assertFalse(guard.verify(self.adb, self.folder)["all_expected_states"])

    def test_tampered_journal_cannot_restore_an_unplanned_package(self):
        plan = self.planned()
        guard.apply(self.adb, self.folder, plan["digest"])
        journal = guard.read_json(self.folder / "journal.json")
        journal["entries"].append({"package": "org.example.notes", "before": 0, "status": "applied"})
        guard.write_json(self.folder / "journal.json", journal)
        writes = list(self.transport.writes)
        with self.assertRaises(guard.GuardError):
            guard.restore(self.adb, self.folder, plan["digest"])
        self.assertEqual(self.transport.writes, writes)

    def test_stale_audit_requires_new_review(self):
        self.audited()
        report = guard.read_json(self.folder / "audit.json")
        report["created_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat()
        guard.write_json(self.folder / "audit.json", report)
        plan = guard.make_plan(self.folder, [FIRST], "Reason", CONTEXT)
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assert_no_writes()

    def test_existing_session_and_existing_plan_are_never_overwritten(self):
        plan = self.planned()
        with self.assertRaises(guard.GuardError):
            self.audited()
        with self.assertRaises(guard.GuardError):
            guard.make_plan(self.folder, [SECOND], "Reason", CONTEXT)
        self.assertEqual(guard.read_json(self.folder / "plan.json")["digest"], plan["digest"])

    def test_session_lock_refuses_parallel_plan_apply_restore_and_verify(self):
        plan = self.planned()
        before = len(self.transport.calls)
        with guard.session_lock(self.folder):
            operations = [
                lambda: guard.make_plan(self.folder, [SECOND], "Reason", CONTEXT),
                lambda: guard.apply(self.adb, self.folder, plan["digest"]),
                lambda: guard.restore(self.adb, self.folder, plan["digest"]),
                lambda: guard.verify(self.adb, self.folder),
            ]
            for operation in operations:
                with self.subTest(operation=operation), self.assertRaisesRegex(guard.GuardError, "locked"):
                    operation()
        self.assertEqual(len(self.transport.calls), before)
        self.assertFalse((self.folder / ".operation.lock").exists())
        self.assert_no_writes()

    def test_lock_is_released_after_normal_execution_error(self):
        plan = self.planned()
        with self.assertRaises(guard.GuardError):
            guard.apply(self.adb, self.folder, "invalid-digest")
        self.assertFalse((self.folder / ".operation.lock").exists())
        guard.apply(self.adb, self.folder, plan["digest"])
        self.assertFalse((self.folder / ".operation.lock").exists())

    def test_stale_lock_is_preserved_instead_of_bypassed(self):
        plan = self.planned()
        lock = self.folder / ".operation.lock"
        lock.write_text("99999999", encoding="ascii")
        with self.assertRaisesRegex(guard.GuardError, "locked"):
            guard.apply(self.adb, self.folder, plan["digest"])
        self.assertEqual(lock.read_text(encoding="ascii"), "99999999")
        self.assert_no_writes()

    def test_missing_keyboard_or_launcher_stops_audit(self):
        for key in ("keyboard", "home"):
            with self.subTest(key=key):
                original = getattr(self.transport, key)
                setattr(self.transport, key, "null")
                with self.assertRaises(guard.GuardError):
                    self.audited()
                setattr(self.transport, key, original)
        self.assert_no_writes()

    def test_native_harmony_without_android_api_and_old_android_stop_before_package_queries(self):
        for sdk in ("", "25"):
            with self.subTest(sdk=sdk):
                self.transport.props["sdk"] = sdk
                with self.assertRaises(guard.GuardError):
                    self.audited()
        self.assert_no_writes()

    def test_unreadable_hidden_missing_or_unknown_package_state_is_rejected(self):
        for output in ("Unable to find package", "User 0: installed=false enabled=0",
                       "User 0: installed=true hidden=true enabled=0",
                       "User 0: installed=true suspended=true enabled=0",
                       "User 0: installed=true enabled=7"):
            with self.subTest(output=output), self.assertRaises(guard.GuardError):
                guard.parse_state(output)

    def test_missing_adb_fails_with_controlled_message(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError("synthetic missing executable")
        with self.assertRaisesRegex(guard.GuardError, "ADB not found"):
            guard.Adb(r"不存在 的工具/adb", runner=missing).connect()

    def test_cli_reports_controlled_failure_for_missing_session(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = guard.main(["plan", "--session", str(self.folder), "--package", FIRST,
                               "--reason", "Reason", "--context-review", CONTEXT])
        self.assertEqual(code, 2)
        self.assertIn('"stopped": true', output.getvalue())

    def test_non_object_or_malformed_session_json_has_controlled_cli_failure(self):
        self.folder.mkdir()
        for raw in ("[]", "null", '"text"', "123", "{not valid JSON}"):
            with self.subTest(raw=raw):
                (self.folder / "audit.json").write_text(raw, encoding="utf-8")
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    code = guard.main(["plan", "--session", str(self.folder), "--package", FIRST,
                                       "--reason", "Reason", "--context-review", CONTEXT])
                self.assertEqual(code, 2)
                self.assertIn('"stopped": true', output.getvalue())
                self.assertNotIn("Traceback", output.getvalue())
        self.assert_no_writes()


if __name__ == "__main__":
    unittest.main()

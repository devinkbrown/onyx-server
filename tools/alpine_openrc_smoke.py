#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Isolated OpenRC asset contract tests; never starts a listening daemon.

Run with Python 3's standard library. Native OpenRC helper/adapter tests skip
when unavailable. These checks do not establish installed-service acceptance.
"""
from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "etc/openrc/onyx-server"
CONFD = ROOT / "etc/openrc/onyx-server.confd"
CHECKPATH = shutil.which("checkpath") or next(
    (str(p) for p in (Path("/usr/libexec/rc/bin/checkpath"),
                      Path("/lib/rc/bin/checkpath")) if p.is_file()), None
)
SETPRIV = shutil.which("setpriv")
ADAPTER = next(
    (p for p in (Path("/usr/libexec/rc/sh/supervise-daemon.sh"),
                 Path("/lib/rc/sh/supervise-daemon.sh")) if p.is_file()), None
)


class OpenRCContract(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="onyx-openrc-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.trace = self.work / "trace"
        self.config = self.work / "candidate.toml"
        self.config.write_text("valid\n")
        self.command = self.work / "daemon-stub"
        self.command.write_text(
            '#!/bin/sh\n'
            'printf "daemon\\n" >> "$TRACE"; printf "%s\\n" "$@" >> "$TRACE"\n'
            '[ "$#" = 2 ] && [ "$1" = --check-config ] || exit 99\n'
            '[ "$(cat "$2")" = valid ]\n'
        )
        self.command.chmod(0o700)
        # Construct a minimal environment: inherited OpenRC/service variables
        # must not select a real service, daemon, or state directory.
        self.env = {
            "PATH": os.defpath,
            "TRACE": str(self.trace),
            "command": str(self.command),
            "config": str(self.config),
            "directory": str(self.work / "state"),
            "command_user": f"{pwd.getpwuid(os.getuid()).pw_name}:"
                            f"{grp.getgrgid(os.getgid()).gr_name}",
        }

    def shell(self, body: str, *, defaults: bool = False,
              native_checkpath: bool = False, native_identity: bool = False) -> subprocess.CompletedProcess[str]:
        helpers = r'''
ebegin() { :; }
eend() { return "$1"; }
service_set_value() { :; }
checkpath() {
    printf 'checkpath\n' >> "$TRACE"; printf '%s\n' "$@" >> "$TRACE"
    [ "${CHECKPATH_STATUS:-0}" = 0 ] || return "$CHECKPATH_STATUS"
    mkdir -p "$directory"
}
setpriv() {
    shift 6
    "$@"
}
supervise-daemon() {
    printf 'supervise\n' >> "$TRACE"; printf '%s\n' "$@" >> "$TRACE"
}
'''
        if native_checkpath:
            helpers += '\ncheckpath() { ' + shlex.quote(CHECKPATH) + ' "$@"; }\n'
        env = {"PATH": os.defpath, "TRACE": str(self.trace)} if defaults else self.env
        if native_identity:
            helpers += '\nunset -f setpriv\n'
        argv = ["/bin/sh", "-c", helpers + '\n. "$1"\n. "$2"\n' + body,
             "onyx-openrc-contract", str(CONFD), str(SERVICE)]
        result = subprocess.run(
            argv, env=env, text=True, capture_output=True, timeout=10,
        )
        return result

    def passed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shell_syntax(self) -> None:
        for path in (SERVICE, CONFD):
            self.passed(subprocess.run(["/bin/sh", "-n", str(path)],
                                       text=True, capture_output=True, timeout=10))

    def test_defaults_foreground_and_bounded_policy(self) -> None:
        result = self.shell(r'''
[ "$supervisor" = supervise-daemon ] &&
[ "$command" = /usr/bin/onyx-server ] &&
[ "$config" = /etc/onyx-server/onyx-server.toml ] &&
[ "$command_user" = onyx-server:onyx-server ] &&
[ "$directory" = /var/lib/onyx-server ] &&
[ "$umask" = 0077 ] &&
[ "$retry" = TERM/30/KILL/5 ] &&
[ "$no_new_privs" = yes ] &&
[ "$extra_commands" = checkconfig ] &&
[ "$extra_started_commands" = reload ] &&
[ "$respawn_delay:$respawn_max:$respawn_period" = 5:3:60 ] &&
[ "${command_background:-false}" = false ] &&
[ -z "${command_args_background:-}" ] &&
[ "$required_files" = "$config" ] &&
[ "$output_logger" = 'logger -t onyx-server -p daemon.info' ] &&
[ "$error_logger" = 'logger -t onyx-server -p daemon.err' ]
''', defaults=True)
        self.passed(result)

    def test_successful_preflight_and_private_state_contract(self) -> None:
        self.passed(self.shell("start_pre"))
        self.assertEqual(self.trace.read_text().splitlines(), [
            "checkpath", "--directory", "--mode", "0700", "--owner",
            self.env["command_user"], self.env["directory"],
            "daemon", "--check-config", str(self.config),
        ])

    def test_invalid_configuration_refuses_start(self) -> None:
        self.config.write_text("invalid\n")
        result = self.shell('start_pre && supervise-daemon forbidden-start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("daemon\n--check-config\n", self.trace.read_text())
        self.assertNotIn("supervise\n", self.trace.read_text())

    def test_missing_configuration_refuses_start(self) -> None:
        self.config.unlink()
        result = self.shell('start_pre && supervise-daemon forbidden-start')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("supervise\n", self.trace.read_text())

    def test_state_failure_prevents_validation_and_start(self) -> None:
        self.env["CHECKPATH_STATUS"] = "1"
        result = self.shell('start_pre && supervise-daemon forbidden-start')
        self.assertNotEqual(result.returncode, 0)
        lines = self.trace.read_text().splitlines()
        self.assertNotIn("daemon", lines)
        self.assertNotIn("supervise", lines)

    def test_reload_preflight_precedes_supervisor_signal(self) -> None:
        self.env["RC_SVCNAME"] = "onyx-isolated-contract"
        Path(self.env["directory"]).mkdir()
        self.passed(self.shell("reload"))
        self.assertEqual(self.trace.read_text().splitlines(), [
            "daemon", "--check-config", str(self.config),
            "supervise", "onyx-isolated-contract", "--signal", "USR2",
        ])

    def test_invalid_candidate_prevents_upgrade_signal(self) -> None:
        Path(self.env["directory"]).mkdir()
        self.config.write_text("invalid\n")
        self.assertNotEqual(self.shell("reload").returncode, 0)
        self.assertNotIn("supervise", self.trace.read_text())

    def test_preflight_uses_daemon_working_directory(self) -> None:
        self.command.write_text('#!/bin/sh\n[ "$PWD" = "$directory" ]\n')
        self.passed(self.shell("start_pre"))

    @unittest.skipUnless(SETPRIV and os.getuid() == 0, "cross-UID check requires an isolated root test environment")
    def test_native_identity_primary_group_and_unreadable_config(self) -> None:
        nobody = pwd.getpwnam("nobody")
        group = grp.getgrgid(nobody.pw_gid).gr_name
        # Cross-UID fixture requires searchable ancestors without changing any
        # existing host path. Place it under the system temporary directory.
        native_temp = tempfile.TemporaryDirectory(prefix="onyx-openrc-identity-", dir="/var/tmp")
        self.addCleanup(native_temp.cleanup)
        self.work = Path(native_temp.name)
        self.config = self.work / "candidate.toml"
        self.config.write_text("valid\n")
        self.command = self.work / "daemon-stub"
        self.trace = self.work / "trace"
        self.env.update(config=str(self.config), command=str(self.command),
                        directory=str(self.work / "state"), TRACE=str(self.trace))
        self.work.chmod(0o755)
        state = Path(self.env["directory"])
        state.mkdir(mode=0o755)
        self.command.write_text('#!/bin/sh\n'
                                '[ "$(id -u)" = "$EXPECT_UID" ] && '
                                '[ "$(id -g)" = "$EXPECT_GID" ] || exit 98\n'
                                '[ "$(cat "$2" 2>/dev/null)" = valid ]\n')
        self.command.chmod(0o755)
        self.env.update(command_user=nobody.pw_name + ":" + group,
                        EXPECT_UID=str(nobody.pw_uid), EXPECT_GID=str(nobody.pw_gid),
                        RC_SVCNAME="onyx-isolated-contract")
        self.config.chmod(0o644)
        self.passed(self.shell("checkconfig", native_identity=True))
        self.config.chmod(0o600)
        # Root can read this candidate while the selected daemon UID cannot.
        self.assertEqual(self.config.read_text(), "valid\n")
        result = self.shell("reload", native_identity=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists(), "upgrade signal after denied identity preflight")
        self.assertNotIn("valid", result.stdout + result.stderr)

    def test_identity_launcher_group_arguments_and_missing_dependency(self) -> None:
        Path(self.env["directory"]).mkdir()
        self.env["command_user"] = "chosen-user:chosen-group"
        result = self.shell(r'''
setpriv() {
    [ "$1:$2:$3:$4:$5:$6" = '--reuid:chosen-user:--regid:chosen-group:--init-groups:--no-new-privs' ] || return 98
    shift 6
    "$@"
}
checkconfig
''')
        self.passed(result)
        self.trace.unlink()
        result = self.shell('setpriv() { return 127; }; reload')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists(), "missing launcher allowed signal or daemon")

    def test_operator_overrides_survive(self) -> None:
        self.env.update(respawn_delay="7", respawn_max="2", respawn_period="90",
                        output_logger="custom-out", error_logger="custom-err")
        self.passed(self.shell(r'''
[ "$respawn_delay:$respawn_max:$respawn_period" = 7:2:90 ] &&
[ "$output_logger:$error_logger" = custom-out:custom-err ] && start_pre
'''))

    @unittest.skipUnless(CHECKPATH, "native OpenRC checkpath unavailable")
    def test_native_checkpath_creates_and_repairs_private_state(self) -> None:
        state = Path(self.env["directory"])
        for existing in (False, True):
            if existing:
                state.chmod(0o755)
            self.passed(self.shell("start_pre", native_checkpath=True))
            info = state.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()))

    @unittest.skipUnless(CHECKPATH, "native OpenRC checkpath unavailable")
    def test_native_checkpath_rejects_file_as_state(self) -> None:
        Path(self.env["directory"]).write_text("not a directory\n")
        result = self.shell("start_pre", native_checkpath=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.trace.exists(), "daemon ran after checkpath failed")

    @unittest.skipUnless(ADAPTER, "native OpenRC supervisor shell adapter unavailable")
    def test_native_adapter_forwards_foreground_and_restart_policy(self) -> None:
        # Source the installed OpenRC adapter, replacing only its process launch
        # and bookkeeping helpers. No OpenRC runtime/state command is executed.
        self.env["RC_SVCNAME"] = "onyx-isolated-contract"
        result = self.shell('. ' + shlex.quote(str(ADAPTER)) + '\nsupervise_start')
        self.passed(result)
        args = self.trace.read_text().splitlines()
        self.assertEqual(args[:3], ["supervise", "onyx-isolated-contract", "--start"])
        for flag, value in (("--retry", "TERM/30/KILL/5"), ("--respawn-delay", "5"), ("--respawn-max", "3"),
                            ("--respawn-period", "60"), ("--umask", "0077"),
                            ("--user", self.env["command_user"]),
                            ("--chdir", self.env["directory"]),
                            ("--stdout-logger", "logger -t onyx-server -p daemon.info"),
                            ("--stderr-logger", "logger -t onyx-server -p daemon.err")):
            self.assertIn(flag, args)
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--no-new-privs", args)
        self.assertEqual(args[-3:], [str(self.command), "--", str(self.config)])


if __name__ == "__main__":
    unittest.main(verbosity=2)

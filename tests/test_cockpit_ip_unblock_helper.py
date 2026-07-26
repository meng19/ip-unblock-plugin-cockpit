import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import types
from unittest import TestCase, mock


def load_helper():
    script = Path(__file__).parents[1] / "usr-local-bin" / "cockpit-ip-unblock-helper"
    loader = importlib.machinery.SourceFileLoader("cockpit_ip_unblock_helper", str(script))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    grp = types.ModuleType("grp")
    grp.getgrnam = lambda name: None
    syslog = types.ModuleType("syslog")
    syslog.LOG_PID = syslog.LOG_AUTH = syslog.LOG_NOTICE = 0
    syslog.openlog = syslog.syslog = syslog.closelog = lambda *args: None
    with mock.patch.dict(sys.modules, {"grp": grp, "syslog": syslog}):
        loader.exec_module(module)
    return module


def ok(stdout=""):
    return type("Result", (), {"ok": True, "stdout": stdout, "stderr": "", "unavailable": False})()


def unavailable(command):
    return type("Result", (), {"ok": False, "stdout": "", "stderr": command, "unavailable": True})()


class IptablesAdapterTests(TestCase):
    def test_iptables_lists_only_ip_specific_drop_or_reject(self):
        """A broad INPUT policy or non-IP source must not be presented as an unblockable IP."""
        helper = load_helper()
        output = "Chain INPUT\nnum target prot opt source destination\n1 DROP all -- 203.0.113.7 0.0.0.0/0\n"
        with mock.patch.object(helper, "run_command", return_value=ok(output)):
            records = helper.IptablesAdapter().list_blocks()
        self.assertEqual(records, [{"source": "iptables", "ip": "203.0.113.7",
                                   "rule": "INPUT: DROP", "target": "DROP", "scope": "runtime"}])

    def test_iptables_excludes_network_wide_and_non_block_rules(self):
        """Only host-specific DROP or REJECT rules should be exposed from -S output."""
        helper = load_helper()
        output = "\n".join([
            "-A INPUT -j DROP",
            "-A INPUT -s 203.0.113.7/32 -j DROP",
            "-A INPUT -s 203.0.113.0/24 -j DROP",
            "-A INPUT -s 2001:db8::7/128 -j REJECT",
            "-A INPUT -s 203.0.113.8/32 -j ACCEPT",
        ])
        with mock.patch.object(helper, "run_command", return_value=ok(output)):
            records = helper.IptablesAdapter().list_blocks()
        self.assertEqual(records, [
            {"source": "iptables", "ip": "203.0.113.7", "rule": "INPUT: DROP", "target": "DROP", "scope": "runtime"},
            {"source": "iptables", "ip": "2001:db8::7", "rule": "INPUT: REJECT", "target": "REJECT", "scope": "runtime"},
        ])

    def test_missing_iptables_is_not_available(self):
        """A missing binary should make the source unavailable without raising."""
        helper = load_helper()
        with mock.patch.object(helper, "run_command", return_value=unavailable("iptables")):
            self.assertFalse(helper.IptablesAdapter().is_available())

    def test_run_command_marks_missing_executable_unavailable(self):
        """A missing executable is reported as an unavailable command rather than an exception."""
        helper = load_helper()
        result = helper.run_command(["definitely-not-an-installed-command"])
        self.assertFalse(result.ok)
        self.assertTrue(result.unavailable)
        self.assertEqual(result.stdout, "")

    def test_iptables_unblock_deletes_the_matching_rule_with_exact_argv(self):
        """Unblocking must delete the discovered source rule, not a mutable line number."""
        helper = load_helper()
        output = "-A INPUT -s 203.0.113.7/32 -p tcp --dport 443 -j DROP\n"
        with mock.patch.object(helper, "run_command", side_effect=[ok(output), ok()]) as run:
            removed = helper.IptablesAdapter().unblock("203.0.113.7")
        self.assertEqual(removed, 1)
        self.assertEqual(run.call_args_list[1].args[0], [
            "iptables", "-D", "INPUT", "-s", "203.0.113.7/32", "-p", "tcp", "--dport", "443", "-j", "DROP",
        ])

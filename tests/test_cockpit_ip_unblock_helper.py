import importlib.machinery
import importlib.util
import io
import json
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

    def test_iptables_excludes_inverted_source_rules(self):
        """An inverted host match blocks its complement and must never be offered for exact-IP deletion."""
        helper = load_helper()
        for line in (
            "-A INPUT ! -s 203.0.113.7/32 -j DROP",
            "-A INPUT -s ! 203.0.113.7/32 -j DROP",
        ):
            with self.subTest(line=line):
                self.assertIsNone(helper.IptablesAdapter._parse_rule(line))

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

    def test_iptables_unblock_preserves_quoted_rule_arguments(self):
        """Deletion must keep quoted -S arguments as one argv element."""
        helper = load_helper()
        output = '-A INPUT -s 203.0.113.7/32 -m comment --comment "temporary block" -j DROP\n'
        with mock.patch.object(helper, "run_command", side_effect=[ok(output), ok()]) as run:
            helper.IptablesAdapter().unblock("203.0.113.7")
        self.assertEqual(run.call_args_list[1].args[0], [
            "iptables", "-D", "INPUT", "-s", "203.0.113.7/32", "-m", "comment", "--comment", "temporary block", "-j", "DROP",
        ])


class Fail2banAdapterTests(TestCase):
    def test_lists_and_unbans_an_ip_in_each_matching_jail(self):
        """Dropping a jail from the status parse would leave one of its bans behind."""
        helper = load_helper()
        status = "Status\n|- Number of jail:      2\n`- Jail list:   sshd, nginx-auth\n"
        sshd = "Status for the jail: sshd\n|- Currently banned: 1\n`- Banned IP list: 203.0.113.7\n"
        nginx = "Status for the jail: nginx-auth\n`- Banned IP list: 203.0.113.7 198.51.100.9\n"
        with mock.patch.object(helper, "run_command", side_effect=[ok(status), ok(sshd), ok(nginx), ok(status), ok(sshd), ok(), ok(nginx), ok()]) as run:
            records = helper.Fail2banAdapter().list_blocks()
            result = helper.Fail2banAdapter().unblock("203.0.113.7")
        self.assertEqual(records, [
            {"source": "fail2ban", "ip": "203.0.113.7", "rule": "sshd", "scope": "runtime"},
            {"source": "fail2ban", "ip": "203.0.113.7", "rule": "nginx-auth", "scope": "runtime"},
            {"source": "fail2ban", "ip": "198.51.100.9", "rule": "nginx-auth", "scope": "runtime"},
        ])
        self.assertEqual(result, {"source": "fail2ban", "status": "success", "removed": 2, "detail": ""})
        self.assertEqual(run.call_args_list[5].args[0], ["fail2ban-client", "set", "sshd", "unbanip", "203.0.113.7"])
        self.assertEqual(run.call_args_list[7].args[0], ["fail2ban-client", "set", "nginx-auth", "unbanip", "203.0.113.7"])

    def test_reports_partial_failure_without_raising(self):
        """A failed jail unban must not prevent another jail's matching ban from being removed."""
        helper = load_helper()
        status = "`- Jail list: sshd, nginx-auth\n"
        jail = "`- Banned IP list: 203.0.113.7\n"
        with mock.patch.object(helper, "run_command", side_effect=[ok(status), ok(jail), ok(), ok(jail), type("Result", (), {"ok": False, "stdout": "", "stderr": "permission denied", "unavailable": False})()]):
            result = helper.Fail2banAdapter().unblock("203.0.113.7")
        self.assertEqual(result, {"source": "fail2ban", "status": "failed", "removed": 1, "detail": "1 of 2 jail unbans failed"})


class FirewalldAdapterTests(TestCase):
    def test_lists_only_exact_host_drop_or_reject_rules_from_both_scopes(self):
        """A parser accepting CIDRs or non-block actions could expose rules broader than the requested host."""
        helper = load_helper()
        runtime = '\n'.join([
            'rule family="ipv4" source address="203.0.113.7" drop',
            'rule family="ipv4" source address="203.0.113.0/24" drop',
            'rule family="ipv4" source address="203.0.113.8" accept',
        ])
        permanent = 'rule family="ipv6" source address="2001:db8::7" reject type="icmp6-port-unreachable"\n'
        with mock.patch.object(helper, "run_command", side_effect=[ok(runtime), ok(permanent)]):
            records = helper.FirewalldAdapter().list_blocks()
        self.assertEqual(records, [
            {"source": "firewalld", "ip": "203.0.113.7", "rule": 'rule family="ipv4" source address="203.0.113.7" drop', "scope": "runtime"},
            {"source": "firewalld", "ip": "2001:db8::7", "rule": 'rule family="ipv6" source address="2001:db8::7" reject type="icmp6-port-unreachable"', "scope": "permanent"},
        ])

    def test_unblock_removes_discovered_rich_rules_with_exact_scope(self):
        """A missing permanent flag or altered rule string would delete the wrong firewalld rule."""
        helper = load_helper()
        rule = 'rule family="ipv4" source address="203.0.113.7" drop'
        with mock.patch.object(helper, "run_command", side_effect=[ok(rule), ok(rule), ok(), ok()]) as run:
            result = helper.FirewalldAdapter().unblock("203.0.113.7")
        self.assertEqual(result, {"source": "firewalld", "status": "success", "removed": 2, "detail": ""})
        self.assertEqual(run.call_args_list[2].args[0], ["firewall-cmd", "--remove-rich-rule", rule])
        self.assertEqual(run.call_args_list[3].args[0], ["firewall-cmd", "--permanent", "--remove-rich-rule", rule])


class UfwAdapterTests(TestCase):
    def test_lists_host_specific_ipv4_and_ipv6_deny_or_reject_rules_only(self):
        """Accepting CIDR, ALLOW, or destination-only rows would make unsafe UFW rules removable."""
        helper = load_helper()
        output = "\n".join([
            "22/tcp                     DENY IN     203.0.113.7",
            "Anywhere                   REJECT IN   2001:db8::7",
            "80/tcp                     DENY IN     203.0.113.0/24",
            "443/tcp                    ALLOW IN    198.51.100.9",
            "22/tcp                     DENY IN     Anywhere",
        ])
        with mock.patch.object(helper, "run_command", return_value=ok(output)):
            records = helper.UfwAdapter().list_blocks()
        self.assertEqual(records, [
            {"source": "ufw", "ip": "203.0.113.7", "rule": "DENY", "scope": "runtime"},
            {"source": "ufw", "ip": "2001:db8::7", "rule": "REJECT", "scope": "runtime"},
        ])

    def test_unblock_uses_force_and_exact_deny_or_reject_argv(self):
        """Omitting --force or changing the action could hang or remove a different UFW rule."""
        helper = load_helper()
        output = "22/tcp DENY IN 203.0.113.7\nAnywhere REJECT IN 203.0.113.7\n"
        with mock.patch.object(helper, "run_command", side_effect=[ok(output), ok(), ok()]) as run:
            result = helper.UfwAdapter().unblock("203.0.113.7")
        self.assertEqual(result, {"source": "ufw", "status": "success", "removed": 2, "detail": ""})
        self.assertEqual(run.call_args_list[1].args[0], ["ufw", "--force", "delete", "deny", "from", "203.0.113.7"])
        self.assertEqual(run.call_args_list[2].args[0], ["ufw", "--force", "delete", "reject", "from", "203.0.113.7"])


class AdapterIntegrationTests(TestCase):
    def test_list_blocked_aggregates_records_from_every_adapter(self):
        """Leaving an adapter out here makes its discovered blocks unreachable from the CLI."""
        helper = load_helper()
        expected = [
            {"source": "iptables", "ip": "203.0.113.7"},
            {"source": "fail2ban", "ip": "203.0.113.8"},
            {"source": "firewalld", "ip": "203.0.113.9"},
            {"source": "ufw", "ip": "203.0.113.10"},
        ]
        adapters = []
        for record in expected:
            adapter = mock.Mock()
            adapter.list_blocks.return_value = [record]
            adapters.append(adapter)
        with mock.patch.object(helper, "IptablesAdapter", return_value=adapters[0]), \
             mock.patch.object(helper, "Fail2banAdapter", return_value=adapters[1]), \
             mock.patch.object(helper, "FirewalldAdapter", return_value=adapters[2]), \
             mock.patch.object(helper, "UfwAdapter", return_value=adapters[3]):
            self.assertEqual(helper.list_blocked(), expected)

    def test_cmd_unblock_aggregates_matching_adapter_results_in_legacy_payload(self):
        """CLI unblocks must reach every source while retaining the existing result fields."""
        helper = load_helper()
        records = [
            {"source": "iptables", "ip": "203.0.113.7"},
            {"source": "fail2ban", "ip": "203.0.113.7"},
            {"source": "firewalld", "ip": "203.0.113.7"},
            {"source": "ufw", "ip": "203.0.113.7"},
        ]
        adapters = []
        for source, removed in (("iptables", 1), ("fail2ban", 2), ("firewalld", 1), ("ufw", 1)):
            adapter = mock.Mock()
            adapter.unblock.return_value = (removed if source == "iptables" else {
                "source": source, "status": "success", "removed": removed, "detail": "",
            })
            adapters.append(adapter)
        output = io.StringIO()
        with mock.patch.object(helper, "list_blocked", return_value=records), \
             mock.patch.object(helper, "IptablesAdapter", return_value=adapters[0]), \
             mock.patch.object(helper, "Fail2banAdapter", return_value=adapters[1]), \
             mock.patch.object(helper, "FirewalldAdapter", return_value=adapters[2]), \
             mock.patch.object(helper, "UfwAdapter", return_value=adapters[3]), \
             mock.patch.object(helper, "get_user", return_value="alice"), \
             mock.patch.object(helper, "is_sudoer", return_value=True), \
             mock.patch.object(helper, "record_history"), \
             mock.patch.object(helper, "audit"), \
             mock.patch("sys.stdout", output):
            helper.cmd_unblock("203.0.113.7")
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["result"], "success")
        self.assertEqual(payload["ip"], "203.0.113.7")
        self.assertEqual(payload["rules_removed"], 5)
        self.assertEqual(payload["source_results"], [
            {"source": "iptables", "status": "success", "removed": 1, "detail": ""},
            {"source": "fail2ban", "status": "success", "removed": 2, "detail": ""},
            {"source": "firewalld", "status": "success", "removed": 1, "detail": ""},
            {"source": "ufw", "status": "success", "removed": 1, "detail": ""},
        ])


class MultiSourceCommandTests(TestCase):
    def _adapter(self, source, available=True, records=None, result=None):
        adapter = mock.Mock()
        adapter.name = source
        adapter.is_available.return_value = available
        adapter.list_blocks.return_value = records or []
        adapter.unblock.return_value = result or {
            "source": source, "status": "not_found", "removed": 0, "detail": "",
        }
        return adapter

    def test_list_payload_reports_available_sources_and_unified_records(self):
        """The list contract must expose every available backend and its source-tagged rows."""
        helper = load_helper()
        adapters = [
            self._adapter("iptables", True, [{"source": "iptables", "ip": "203.0.113.7"}]),
            self._adapter("fail2ban", False),
            self._adapter("firewalld", True, [{"source": "firewalld", "ip": "203.0.113.8"}]),
            self._adapter("ufw", True, [{"source": "ufw", "ip": "203.0.113.9"}]),
        ]
        with mock.patch.object(helper, "get_adapters", return_value=adapters), \
             mock.patch.object(helper, "get_quota", return_value=(5, 5, False)):
            payload = helper.build_list_payload("alice")
        self.assertEqual(payload["available_sources"], ["iptables", "firewalld", "ufw"])
        self.assertEqual(payload["blocked_ips"], [
            {"source": "iptables", "ip": "203.0.113.7"},
            {"source": "firewalld", "ip": "203.0.113.8"},
            {"source": "ufw", "ip": "203.0.113.9"},
        ])

    def test_list_payload_reports_bulk_permission_from_authorization(self):
        """The bulk control must be available exactly to authorized users."""
        helper = load_helper()
        with mock.patch.object(helper, "get_adapters", return_value=[]), \
             mock.patch.object(helper, "get_quota", return_value=(5, 5, False)), \
             mock.patch.object(helper, "is_authorized", side_effect=[True, False]):
            authorized = helper.build_list_payload("alice")
            unauthorized = helper.build_list_payload("bob")
        self.assertIs(authorized["can_bulk_unblock"], True)
        self.assertIs(unauthorized["can_bulk_unblock"], False)

    def test_all_attempts_every_available_source_and_isolates_failure(self):
        """A failed backend cannot prevent later available sources from being attempted."""
        helper = load_helper()
        iptables = self._adapter("iptables", True, result={
            "source": "iptables", "status": "success", "removed": 1, "detail": "",
        })
        fail2ban = self._adapter("fail2ban", True, result={
            "source": "fail2ban", "status": "failed", "removed": 0, "detail": "denied",
        })
        firewalld = self._adapter("firewalld", True, result={
            "source": "firewalld", "status": "success", "removed": 2, "detail": "",
        })
        with mock.patch.object(helper, "get_adapters", return_value=[iptables, fail2ban, firewalld]), \
             mock.patch.object(helper, "consume_quota", return_value=(4, 5, False)) as consume, \
             mock.patch.object(helper, "record_history") as history:
            payload = helper.unblock_ip("alice", "203.0.113.7", "all")
        self.assertEqual(payload["result"], "partial")
        self.assertEqual(payload["rules_removed"], 3)
        self.assertEqual(payload["source_results"], [
            iptables.unblock.return_value, fail2ban.unblock.return_value, firewalld.unblock.return_value,
        ])
        consume.assert_called_once_with("alice")
        history.assert_called_once_with("alice", "203.0.113.7", "iptables, firewalld")

    def test_requested_source_only_invokes_that_source(self):
        """Selecting one source must not touch any other backend."""
        helper = load_helper()
        iptables = self._adapter("iptables", True)
        fail2ban = self._adapter("fail2ban", True, result={
            "source": "fail2ban", "status": "success", "removed": 1, "detail": "",
        })
        with mock.patch.object(helper, "get_adapters", return_value=[iptables, fail2ban]), \
             mock.patch.object(helper, "consume_quota", return_value=(4, 5, False)), \
             mock.patch.object(helper, "record_history") as history:
            payload = helper.unblock_ip("alice", "203.0.113.7", "fail2ban")
        self.assertEqual(payload["result"], "success")
        iptables.unblock.assert_not_called()
        fail2ban.unblock.assert_called_once_with("203.0.113.7")
        history.assert_called_once_with("alice", "203.0.113.7", "fail2ban")

    def test_no_removal_does_not_consume_quota_or_record_history(self):
        """Quota and history advance only after at least one deletion succeeds."""
        helper = load_helper()
        adapter = self._adapter("ufw", True)
        with mock.patch.object(helper, "get_adapters", return_value=[adapter]), \
             mock.patch.object(helper, "consume_quota") as consume, \
             mock.patch.object(helper, "record_history") as history, \
             mock.patch.object(helper, "get_quota", return_value=(5, 5, False)):
            payload = helper.unblock_ip("alice", "203.0.113.7", "all")
        self.assertEqual(payload["result"], "failure")
        self.assertEqual(payload["rules_removed"], 0)
        consume.assert_not_called()
        history.assert_not_called()

    def test_parse_cli_rejects_invalid_duplicate_or_valueless_source(self):
        """Only one explicit source from the fixed allow-list is valid for unblock."""
        helper = load_helper()
        for args in (
            ["unblock", "203.0.113.7", "--source", "nftables"],
            ["unblock", "203.0.113.7", "--source", "iptables", "--source", "ufw"],
            ["unblock", "203.0.113.7", "--source"],
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    helper.parse_cli(args)

    def test_parse_cli_accepts_each_allowed_source(self):
        """The CLI accepts all four concrete sources plus the all-sources selector."""
        helper = load_helper()
        for source in ("all", "iptables", "fail2ban", "firewalld", "ufw"):
            with self.subTest(source=source):
                parsed = helper.parse_cli(["unblock", "203.0.113.7", "--source", source])
                self.assertEqual(parsed["source"], source)

    def test_parse_cli_accepts_location_lookup_language(self):
        """The frontend location lookup uses a strict helper command instead of browser fetch."""
        helper = load_helper()
        self.assertEqual(helper.parse_cli(["locate-ip", "8.8.8.8", "zh"]), {
            "command": "locate-ip", "ip": "8.8.8.8", "lang": "zh",
        })
        with self.assertRaises(ValueError):
            helper.parse_cli(["locate-ip", "8.8.8.8", "de"])

    def test_locate_ip_skips_reserved_addresses_and_formats_public_results(self):
        """Reserved IPs should not call an external service; public results should become display text."""
        helper = load_helper()
        with mock.patch.object(helper, "_fetch_json") as fetch:
            self.assertEqual(helper.locate_ip("203.0.113.7"), {
                "status": "reserved", "ip": "203.0.113.7",
            })
            fetch.assert_not_called()

        with mock.patch.object(helper, "_fetch_json", return_value={
            "status": "success", "country": "美国", "regionName": "加利福尼亚州", "city": "聖荷西",
        }) as fetch:
            self.assertEqual(helper.locate_ip("8.8.8.8", "zh"), {
                "status": "success", "ip": "8.8.8.8", "text": "美国 · 加利福尼亚州 · 圣荷西",
            })
            self.assertIn("ip-api.com", fetch.call_args.args[0])

    def test_parse_cli_rejects_force_quota_bypass(self):
        """A caller allowed to run the helper must not opt itself out of quota accounting."""
        helper = load_helper()
        with self.assertRaises(ValueError):
            helper.parse_cli(["unblock", "203.0.113.7", "--force"])


class BulkUnblockCommandTests(TestCase):
    def _payload(self, ip, result="success", removed=1, remaining=-1, unlimited=True):
        return {
            "result": result, "ip": ip, "rules_removed": removed,
            "source_results": [], "quota_remaining": remaining,
            "quota_limit": -1 if unlimited else 2, "unlimited": unlimited,
        }

    def test_parse_cli_accepts_only_strict_bulk_unblock_grammar(self):
        """Bulk requests need a source selector followed by one or more IP operands."""
        helper = load_helper()
        parsed = helper.parse_cli([
            "bulk-unblock", "--source", "fail2ban", "203.0.113.7", "2001:db8::7",
        ])
        self.assertEqual(parsed, {
            "command": "bulk-unblock", "source": "fail2ban",
            "ips": ["203.0.113.7", "2001:db8::7"],
        })
        for args in (
            ["bulk-unblock", "203.0.113.7", "--source", "all"],
            ["bulk-unblock", "--source", "nftables", "203.0.113.7"],
            ["bulk-unblock", "--source", "all"],
            ["bulk-unblock", "--source", "all", "203.0.113.7", "--source", "ufw"],
            ["bulk-unblock", "--source", "all"] + ["203.0.113.7"] * 101,
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    helper.parse_cli(args)

    def test_cmd_bulk_unblock_rejects_unauthorized_user_before_processing(self):
        """The helper must enforce policy even if an untrusted client exposes bulk controls."""
        helper = load_helper()
        output = io.StringIO()
        with mock.patch.object(helper, "get_user", return_value="alice"), \
             mock.patch.object(helper, "is_authorized", return_value=False), \
             mock.patch.object(helper, "unblock_ip") as unblock, \
             mock.patch("sys.stdout", output):
            helper.cmd_bulk_unblock(["203.0.113.7"], "all")
        self.assertEqual(json.loads(output.getvalue()), {
            "result": "failure", "error": "sudo membership required",
        })
        unblock.assert_not_called()

    def test_sudo_bulk_processes_every_ip_and_forwards_source(self):
        """Sudo users bypass the daily cap but retain per-IP source-aware results."""
        helper = load_helper()
        ips = ["203.0.113.7", "203.0.113.8"]
        with mock.patch.object(helper, "is_sudoer", return_value=True), \
             mock.patch.object(helper, "unblock_ip", side_effect=[
                 self._payload(ips[0]), self._payload(ips[1]),
             ]) as unblock:
            payload = helper.bulk_unblock("admin", ips, "ufw")
        self.assertEqual([call.args for call in unblock.call_args_list], [
            ("admin", ips[0], "ufw"), ("admin", ips[1], "ufw"),
        ])
        self.assertEqual(payload["unprocessed_ips"], [])
        self.assertEqual(payload["summary"], {
            "requested": 2, "processed": 2, "success": 2,
            "partial": 0, "failure": 0, "rules_removed": 2,
        })

    def test_regular_bulk_stops_after_success_exhausts_quota(self):
        """A regular user must leave later IPs untouched once a successful unblock uses the last slot."""
        helper = load_helper()
        ips = ["203.0.113.7", "203.0.113.8", "203.0.113.9"]
        with mock.patch.object(helper, "is_sudoer", return_value=False), \
             mock.patch.object(helper, "get_quota", side_effect=[(1, 2, False), (0, 2, False), (0, 2, False)]), \
             mock.patch.object(helper, "unblock_ip", return_value=self._payload(
                 ips[0], remaining=0, unlimited=False)) as unblock:
            payload = helper.bulk_unblock("alice", ips, "all")
        unblock.assert_called_once_with("alice", ips[0], "all")
        self.assertEqual(payload["unprocessed_ips"], ips[1:])
        self.assertEqual(payload["summary"]["processed"], 1)

    def test_policy_unlimited_regular_user_does_not_stop_batch(self):
        """A zero policy cap remains unlimited for regular users, as in the single-IP path."""
        helper = load_helper()
        ips = ["203.0.113.7", "203.0.113.8"]
        with mock.patch.object(helper, "is_sudoer", return_value=False), \
             mock.patch.object(helper, "get_quota", return_value=(-1, -1, True)), \
             mock.patch.object(helper, "unblock_ip", side_effect=[
                 self._payload(ips[0]), self._payload(ips[1]),
             ]) as unblock:
            payload = helper.bulk_unblock("alice", ips, "all")
        self.assertEqual(unblock.call_count, 2)
        self.assertEqual(payload["unprocessed_ips"], [])

    def test_bulk_isolates_one_ip_failure_and_continues(self):
        """An unexpected per-IP failure cannot suppress later independent unblocks."""
        helper = load_helper()
        ips = ["203.0.113.7", "203.0.113.8"]
        with mock.patch.object(helper, "is_sudoer", return_value=True), \
             mock.patch.object(helper, "unblock_ip", side_effect=[RuntimeError("backend down"),
                 self._payload(ips[1])]):
            payload = helper.bulk_unblock("admin", ips, "all")
        self.assertEqual(payload["results"][0]["result"], "failure")
        self.assertEqual(payload["results"][0]["ip"], ips[0])
        self.assertEqual(payload["results"][1]["result"], "success")
        self.assertEqual(payload["summary"]["failure"], 1)
        self.assertEqual(payload["summary"]["success"], 1)


class TrustedIdentityTests(TestCase):
    def test_sudo_identity_cannot_be_overridden_by_cli_or_cockpit_values(self):
        """Quota and sudo membership must use sudo's authenticated invoking user."""
        helper = load_helper()
        helper._CLI_USER = "root"
        with mock.patch.dict(helper.os.environ, {
            "SUDO_USER": "alice",
            "COCKPIT_USER": "mallory",
        }, clear=True):
            self.assertEqual(helper.get_user(), "alice")

    def test_cockpit_identity_is_used_when_no_sudo_identity_exists(self):
        """Cockpit's authenticated identity remains available for non-sudo invocation."""
        helper = load_helper()
        with mock.patch.dict(helper.os.environ, {"COCKPIT_USER": "alice"}, clear=True):
            self.assertEqual(helper.get_user(), "alice")


class FirewalldRuleParsingTests(TestCase):
    def test_excludes_block_actions_followed_by_malformed_limiter_tokens(self):
        """A bare limiter after an action is malformed and must not be removable."""
        helper = load_helper()
        self.assertIsNone(helper.FirewalldAdapter._parse_rule(
            'rule source address="203.0.113.7" drop limit'
        ))

    def test_excludes_non_terminal_action_words_in_log_prefix_or_quoted_fields(self):
        """A log prefix or quoted option mentioning drop/reject is not a blocking action."""
        helper = load_helper()
        self.assertIsNone(helper.FirewalldAdapter._parse_rule(
            'rule family="ipv4" source address="203.0.113.7" log prefix="drop" accept'
        ))
        self.assertIsNone(helper.FirewalldAdapter._parse_rule(
            'rule family="ipv4" source address="203.0.113.7" accept log prefix="reject"'
        ))
        self.assertIsNone(helper.FirewalldAdapter._parse_rule(
            'rule family="ipv4" source address="203.0.113.7" drop accept'
        ))


class FrontendContractTests(TestCase):
    def test_page_exposes_source_selector_and_source_aware_columns(self):
        """The UI needs a labelled selector plus source and rule-detail columns."""
        html = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="source-filter"', html)
        self.assertIn('data-i18n="blockSource"', html)
        self.assertIn('data-i18n="ruleDetail"', html)

    def test_script_passes_selected_source_and_preserves_history_order(self):
        """Selecting a source must reach the helper without mutating the fetched history."""
        script = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('"--source", selectedSource', script)
        self.assertIn('history.slice().reverse()', script)

    def test_script_uses_authenticated_sudo_identity_and_all_source_selection(self):
        """Cockpit must not pass a spoofable user and All must reach the backend as all."""
        script = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertNotIn('fullArgs.push("--user"', script)
        self.assertIn('openConfirm(this.getAttribute("data-ip"), selectedSource(),', script)

    def test_script_renders_structured_source_results_with_safe_badges(self):
        """Result details and source labels must be rendered as text, not injected markup."""
        script = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('source_results', script)
        self.assertIn('source-badge', script)
        self.assertIn('.textContent =', script)

    def test_recent_table_hides_headers_when_empty_and_shows_source_location_columns(self):
        """Recent records must not leave table headers behind and should show richer context."""
        root = Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock"
        html = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('data-i18n="recentTime"', html)
        self.assertIn('data-i18n="recentIp"', html)
        self.assertIn('data-i18n="blockSource"', html)
        self.assertIn('data-i18n="target"', html)
        self.assertIn('id="recent-table-wrap"', html)
        self.assertIn('class="table-wrap"', html)
        self.assertIn('body.innerHTML = ""', script)
        self.assertIn('appendSourceBadges(tdSource, rec.source)', script)
        self.assertIn('renderLocationCell(tdLocation, rec.ip)', script)

    def test_bulk_ui_has_authorized_selection_controls_and_confirmation(self):
        """Batch controls must be gated by the list capability and include accessible selection UI."""
        root = Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock"
        html = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('id="select-all-blocked"', html)
        self.assertIn('id="bulk-unblock-btn"', html)
        self.assertIn('id="bulk-confirm-overlay"', html)
        self.assertIn('currentData.can_bulk_unblock', script)
        self.assertIn('selectedBulkIps', script)
        self.assertIn('toggleCurrentPageBulkSelection()', script)
        self.assertIn('closest("#select-all-blocked")', script)

    def test_bulk_ui_calls_source_aware_helper_and_reports_unprocessed_ips(self):
        """Batch requests must preserve the selected source and surface backend partial processing."""
        script = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('["bulk-unblock", "--source", source]', script)
        self.assertIn('unprocessed_ips', script)
        self.assertIn('summary', script)
        self.assertIn('selectedBulkIps = {}', script)

    def test_location_lookup_uses_helper_not_browser_external_fetch(self):
        """Cockpit pages should not depend on direct browser fetches to third-party location APIs."""
        script = (Path(__file__).parents[1] / "usr-share-cockpit-ip-unblock" / "ip-unblock.js").read_text(encoding="utf-8")
        self.assertIn('["locate-ip", ip, curLang]', script)
        self.assertNotIn('fetch("https://ipwho.is/', script)

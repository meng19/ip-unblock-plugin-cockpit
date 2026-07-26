import json
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from test_cockpit_ip_unblock_helper import load_helper


class PolicyConfigurationTests(TestCase):
    def test_sudo_user_is_unlimited_even_when_policy_sets_a_limit(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"access_mode": "sudo_only", "daily_unblock_limit": 2,
                                        "show_recent_history": False}), encoding="utf-8")
            with mock.patch.object(helper, "CONFIG_FILE", str(path)), \
                 mock.patch.object(helper, "is_sudoer", return_value=True):
                self.assertEqual(helper.get_quota("admin"), (-1, -1, True))

    def test_policy_limit_applies_to_regular_user(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"access_mode": "all_users", "daily_unblock_limit": 2,
                                        "show_recent_history": True}), encoding="utf-8")
            with mock.patch.object(helper, "CONFIG_FILE", str(path)), \
                 mock.patch.object(helper, "is_sudoer", return_value=False), \
                 mock.patch.object(helper, "load_state", return_value={}):
                self.assertEqual(helper.get_quota("regular"), (2, 2, False))

    def test_invalid_policy_uses_safe_defaults(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"daily_unblock_limit": -1}', encoding="utf-8")
            with mock.patch.object(helper, "CONFIG_FILE", str(path)), \
                 mock.patch.object(helper, "audit"):
                self.assertEqual(helper.load_policy(), helper.DEFAULT_POLICY)

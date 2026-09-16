import unittest
from unittest.mock import ANY, patch

from detector.dynamic import run_dynamic_juice_shop as runner


class JuiceShopRunnerTests(unittest.TestCase):
    @patch.object(runner, "check_juice_shop_endpoint_errors", return_value=[])
    @patch.object(runner, "check_juice_shop_anonymous_admin_access", return_value=[])
    @patch.object(runner, "check_juice_shop_anonymous_basket_access", return_value=[])
    @patch.object(runner, "check_juice_shop_security_headers", return_value=[])
    @patch.object(runner, "check_juice_shop_reflected_input", return_value=[])
    @patch.object(runner, "check_juice_shop_search_errors", return_value=[])
    @patch.object(runner, "check_juice_shop_cors", return_value=[])
    def test_anonymous_scan_does_not_attempt_login(
        self,
        check_cors,
        check_search_errors,
        check_reflected_input,
        check_security_headers,
        check_anonymous_basket,
        check_anonymous_admin,
        check_endpoint_errors,
    ):
        with patch.object(runner, "login_juice_shop") as login:
            findings, account = runner.run_juice_shop_checks("http://juice-shop")

        self.assertEqual(findings, [])
        self.assertIsNone(account)
        login.assert_not_called()

    @patch.object(runner, "check_juice_shop_cross_account_basket", return_value=[])
    @patch.object(runner, "check_juice_shop_endpoint_errors", return_value=[])
    @patch.object(runner, "check_juice_shop_authenticated_user_area", return_value=[])
    @patch.object(runner, "verify_juice_shop_account", side_effect=[
        {"email": "one@example.com", "id": 1},
        {"email": "two@example.com", "id": 2},
    ])
    @patch.object(runner, "login_juice_shop")
    @patch.object(runner, "check_juice_shop_anonymous_admin_access", return_value=[])
    @patch.object(runner, "check_juice_shop_anonymous_basket_access", return_value=[])
    @patch.object(runner, "check_juice_shop_security_headers", return_value=[])
    @patch.object(runner, "check_juice_shop_reflected_input", return_value=[])
    @patch.object(runner, "check_juice_shop_search_errors", return_value=[])
    @patch.object(runner, "check_juice_shop_cors", return_value=[])
    def test_authenticated_scan_runs_account_checks(
        self,
        check_cors,
        check_search_errors,
        check_reflected_input,
        check_security_headers,
        check_anonymous_basket,
        check_anonymous_admin,
        login,
        verify_account,
        check_endpoint_errors,
        check_user_area,
        check_cross_account,
    ):
        findings, account = runner.run_juice_shop_checks(
            "http://juice-shop",
            email="one@example.com",
            password="secret",
            second_email="two@example.com",
            second_password="secret2",
            basket_id=7,
        )

        self.assertEqual(findings, [])
        self.assertTrue(account["cross_account_checked"])
        self.assertEqual(account["primary"]["id"], 1)
        self.assertEqual(account["secondary"]["id"], 2)
        self.assertEqual(login.call_count, 2)
        check_user_area.assert_called_once()
        check_cross_account.assert_called_once_with(ANY, "http://juice-shop", 7)


if __name__ == "__main__":
    unittest.main()
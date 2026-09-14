import argparse
import json
import os

import requests

from detector.dynamic.juice_shop_checks import (
    check_juice_shop_anonymous_admin_access,
    check_juice_shop_anonymous_basket_access,
    check_juice_shop_cross_account_basket,
    check_juice_shop_cors,
    check_juice_shop_reflected_input,
    check_juice_shop_security_headers,
    check_juice_shop_search_errors,
    login_juice_shop,
    verify_juice_shop_account,
    check_juice_shop_authenticated_user_area,
)
from detector.scoring.scorer import build_scan_report


def run_juice_shop_checks(
    base_url: str = "http://localhost:3000",
    email: str | None = None,
    password: str | None = None,
    second_email: str | None = None,
    second_password: str | None = None,
    basket_id: int = 1,
) -> tuple[list[dict], dict | None]:
    session = requests.Session()
    findings = []
    findings += check_juice_shop_cors(session, base_url)
    findings += check_juice_shop_search_errors(session, base_url)
    findings += check_juice_shop_reflected_input(session, base_url)
    findings += check_juice_shop_security_headers(session, base_url)
    session.headers.pop("Authorization", None)
    findings += check_juice_shop_anonymous_basket_access(session, base_url)
    findings += check_juice_shop_anonymous_admin_access(session, base_url)

    if email or password:
        if not email or not password:
            raise ValueError("Juice Shop email and password must be provided together")
        login_juice_shop(session, base_url, email, password)
        account = verify_juice_shop_account(session, base_url, email)
        findings += check_juice_shop_authenticated_user_area(session, base_url)
        auth_context = {"primary": account, "secondary": None, "cross_account_checked": False}
        if second_email or second_password:
            if not second_email or not second_password:
                raise ValueError("Second Juice Shop email and password must be provided together")
            second_session = requests.Session()
            login_juice_shop(second_session, base_url, second_email, second_password)
            second_account = verify_juice_shop_account(second_session, base_url, second_email)
            findings += check_juice_shop_cross_account_basket(second_session, base_url, basket_id)
            auth_context["secondary"] = second_account
            auth_context["cross_account_checked"] = True
        return findings, auth_context
    return findings, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run public API checks against OWASP Juice Shop")
    parser.add_argument("--url", default="http://localhost:3000", help="Juice Shop base URL")
    parser.add_argument("--email", default=os.getenv("JUICE_SHOP_EMAIL"), help="Optional Juice Shop email")
    parser.add_argument("--password", default=os.getenv("JUICE_SHOP_PASSWORD"), help="Optional Juice Shop password")
    parser.add_argument("--second-email", default=os.getenv("JUICE_SHOP_SECOND_EMAIL"), help="Optional second test account email")
    parser.add_argument("--second-password", default=os.getenv("JUICE_SHOP_SECOND_PASSWORD"), help="Optional second test account password")
    parser.add_argument("--basket-id", type=int, default=1, help="Basket ID owned by the first test account")
    args = parser.parse_args()

    print(f"Starting Juice Shop checks against {args.url}...")
    results, account = run_juice_shop_checks(
        args.url,
        args.email,
        args.password,
        args.second_email,
        args.second_password,
        args.basket_id,
    )
    report = build_scan_report(args.url, results)
    report["authentication"] = {
        "checked": account is not None,
        "account": account,
    }
    print(json.dumps(report, indent=2))
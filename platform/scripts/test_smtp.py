#!/usr/bin/env python3
"""Validate SMTP config by sending real test email.

Usage:
    python scripts/test_smtp.py [--to you@example.com]

Reads SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_USE_TLS from app.config
(i.e. from .env). Exits non-zero on failure.
"""
import argparse
import smtplib
import socket
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import (  # noqa: E402
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS,
    CVE_EMAIL_SENDER, CVE_EMAIL_SENDER_NAME,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", default=CVE_EMAIL_SENDER, help="recipient for test email")
    ap.add_argument("--dry-run", action="store_true", help="only test connect+login, no send")
    args = ap.parse_args()

    print(f"HOST={SMTP_HOST} PORT={SMTP_PORT} USER={SMTP_USER!r} TLS={SMTP_USE_TLS}")

    if not SMTP_HOST:
        print("FAIL: SMTP_HOST not set")
        return 1
    if not SMTP_USER or not SMTP_PASS:
        print("FAIL: SMTP_USER / SMTP_PASS not set")
        return 1

    try:
        if SMTP_USE_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
    except (socket.error, smtplib.SMTPException) as e:
        print(f"FAIL: connect error: {e}")
        return 1

    try:
        server.login(SMTP_USER, SMTP_PASS)
        print("OK: login success")

        if args.dry_run:
            print("OK: dry-run, skip send")
            return 0

        from_addr = formataddr((CVE_EMAIL_SENDER_NAME, CVE_EMAIL_SENDER)) if CVE_EMAIL_SENDER_NAME else CVE_EMAIL_SENDER

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "SMTP config test"
        msg["From"] = from_addr
        msg["To"] = args.to
        body = f"SMTP test email sent {datetime.utcnow().isoformat()}Z via {SMTP_HOST}:{SMTP_PORT}"
        msg.attach(MIMEText(body, "plain", "utf-8"))

        server.sendmail(CVE_EMAIL_SENDER, [args.to], msg.as_string())
        print(f"OK: test email sent to {args.to}")
        return 0
    except smtplib.SMTPAuthenticationError as e:
        print(f"FAIL: auth error: {e}")
        return 1
    except smtplib.SMTPException as e:
        print(f"FAIL: send error: {e}")
        return 1
    finally:
        try:
            server.quit()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

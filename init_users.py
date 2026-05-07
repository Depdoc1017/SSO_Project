"""Create starter SSO users with salted password hashes.

Default demo accounts:
  admin / AdminPass123!
  auditor / AuditPass123!

For a real deployment, change these immediately.
"""

from __future__ import annotations

import json
from pathlib import Path

from sso.security import DATA_DIR, USERS_FILE, make_user_record


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    users = [
        make_user_record("admin", "AdminPass123!", "Administrator"),
        make_user_record("auditor", "AuditPass123!", "Auditor"),
    ]
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")
    print(f"Created {USERS_FILE}")
    print("Demo accounts:")
    print("  admin / AdminPass123!")
    print("  auditor / AuditPass123!")


if __name__ == "__main__":
    main()

"""Authentication and role-based access control for Secure System Observer."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.json"
AUDIT_LOG = DATA_DIR / "audit.log"

PBKDF2_ITERATIONS = 200_000
HASH_NAME = "sha256"


class AuthError(Exception):
    """Raised when authentication fails."""


class AccessDenied(Exception):
    """Raised when a user attempts an action outside their role."""


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def audit_event(event_type: str, message: str, username: str = "unknown") -> None:
    """Append an audit event or security alert to the audit log."""
    ensure_data_dir()
    timestamp = datetime.now().isoformat(timespec="seconds")
    uid = os.getuid() if hasattr(os, "getuid") else "N/A"
    line = f"{timestamp} | uid={uid} | user={username} | {event_type}: {message}\n"
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(line)


def hash_password(password: str, salt_hex: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a per-user salt."""
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return digest.hex()


def make_user_record(username: str, password: str, role: str) -> Dict[str, str | int]:
    if role not in {"Administrator", "Auditor"}:
        raise ValueError("Role must be Administrator or Auditor")
    salt_hex = secrets.token_bytes(16).hex()
    return {
        "username": username,
        "role": role,
        "salt": salt_hex,
        "password_hash": hash_password(password, salt_hex),
        "iterations": PBKDF2_ITERATIONS,
        "hash_algorithm": "PBKDF2-HMAC-SHA256",
    }


def load_users() -> Dict[str, Dict[str, str]]:
    ensure_data_dir()
    if not USERS_FILE.exists():
        raise AuthError("users.json not found. Run: python init_users.py")
    with USERS_FILE.open("r", encoding="utf-8") as f:
        users = json.load(f)
    return {u["username"]: u for u in users}


def authenticate(username: str, password: str) -> Optional[Dict[str, str]]:
    users = load_users()
    record = users.get(username)
    if not record:
        audit_event("FAILED_LOGIN", "Unknown username", username)
        return None

    attempted = hash_password(password, record["salt"])
    stored = record["password_hash"]

    if hmac.compare_digest(attempted, stored):
        audit_event("LOGIN_SUCCESS", f"Logged in as {record['role']}", username)
        return {"username": username, "role": record["role"]}

    audit_event("FAILED_LOGIN", "Bad password", username)
    return None


def require_role(user: Dict[str, str], allowed_roles: set[str], action: str) -> None:
    """Enforce RBAC and log blocked actions as security alerts."""
    role = user.get("role", "unknown")
    username = user.get("username", "unknown")
    if role not in allowed_roles:
        audit_event(
            "SECURITY_ALERT",
            f"Access denied for action '{action}'. Required={sorted(allowed_roles)}, actual={role}",
            username,
        )
        raise AccessDenied(f"Access denied: {role} cannot perform '{action}'.")


def prompt_login(max_attempts: int = 3) -> Dict[str, str]:
    """Prompt for credentials and return the authenticated user record."""
    for attempt in range(1, max_attempts + 1):
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        user = authenticate(username, password)
        if user:
            return user
        print(f"Invalid login. Attempts left: {max_attempts - attempt}")
    raise AuthError("Too many failed login attempts.")

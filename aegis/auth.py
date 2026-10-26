"""Operator accounts, sign-in sessions and role permissions.

Accounts live in data/users.json with PBKDF2-SHA256 password hashes; create
them with `python -m aegis.users add`. A successful sign-in returns a session
token (HMAC-signed with a key kept outside the project) that every API call
presents. The server, not the console, decides what each role may do, and the
audit trail records the signed-in account rather than a typed name.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

from . import config, keys

ROLES = {
    "analyst": "SOC Analyst",
    "responder": "Incident Responder",
    "manager": "Security Manager",
    "researcher": "Researcher",
}

# Who may do what. Everyone signed in may read runs and verify audit trails.
PERMISSIONS = {
    "run": {"analyst", "manager"},
    "review": {"analyst", "responder", "manager"},
    "control": {"manager"},
}

USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")
ITERATIONS = 310_000


class AuthError(Exception):
    pass


def can(role: str, permission: str) -> bool:
    return role in PERMISSIONS[permission]


# --- passwords -----------------------------------------------------------------

def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITERATIONS).hex()
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
    return hmac.compare_digest(candidate, digest)


# --- accounts ------------------------------------------------------------------

def load_users() -> dict:
    if not config.USERS_FILE.exists():
        return {}
    return json.loads(config.USERS_FILE.read_text(encoding="utf-8"))


def _save_users(users: dict) -> None:
    config.USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.USERS_FILE.write_text(json.dumps(users, indent=1), encoding="utf-8")


def add_user(username: str, password: str, role: str, name: str | None = None) -> dict:
    username = username.strip().lower()
    if not USERNAME.match(username):
        raise ValueError("Username must be 3-32 characters: a-z, 0-9, dot, dash or underscore.")
    if role not in ROLES:
        raise ValueError(f"Role must be one of: {', '.join(ROLES)}.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    users = load_users()
    users[username] = {"name": (name or username).strip(), "role": role, "password": hash_password(password)}
    _save_users(users)
    return public(username, users[username])


def remove_user(username: str) -> bool:
    users = load_users()
    if users.pop(username, None) is None:
        return False
    _save_users(users)
    return True


def public(username: str, record: dict) -> dict:
    return {"username": username, "name": record["name"], "role": record["role"], "role_label": ROLES[record["role"]]}


def authenticate(username: str, password: str) -> dict:
    users = load_users()
    if not users:
        raise AuthError("No operator accounts exist yet. Create one with: python -m aegis.users add <username> --role analyst")
    record = users.get(username.strip().lower())
    # Hash even for unknown users so response time does not reveal which names exist.
    stored = record["password"] if record else hash_password("x", "0" * 32)
    if not check_password(password, stored) or record is None:
        raise AuthError("Wrong username or password.")
    return public(username.strip().lower(), record)


# --- session tokens ------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(user: dict) -> dict:
    expires = int(time.time()) + config.SESSION_HOURS * 3600
    payload = _b64(json.dumps({"sub": user["username"], "exp": expires}).encode())
    signature = _b64(hmac.new(keys.auth_secret(), payload.encode(), hashlib.sha256).digest())
    return {"token": f"{payload}.{signature}", "expires_at": expires, "user": user}


def read_token(token: str) -> dict:
    """Return the current account for a token; the role is re-read from the account file."""
    try:
        payload, signature = token.split(".")
        expected = _b64(hmac.new(keys.auth_secret(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise AuthError("Invalid session.")
        claims = json.loads(_unb64(payload))
    except (ValueError, json.JSONDecodeError) as error:
        raise AuthError("Invalid session.") from error
    if claims.get("exp", 0) < time.time():
        raise AuthError("Session expired. Sign in again.")
    record = load_users().get(claims.get("sub"))
    if record is None:
        raise AuthError("Account no longer exists.")
    return public(claims["sub"], record)

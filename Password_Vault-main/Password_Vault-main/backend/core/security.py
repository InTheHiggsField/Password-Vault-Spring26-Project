import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta

from passlib.context import CryptContext
from backend.app.config import SESSION_SECRET

# ---------------------------------------------------------------------------
# Password Hashing (authKey)
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_auth_key(auth_key: str) -> str:
    """
    Bcrypt-hashes the PBKDF2-derived authKey before storing in the DB.
    The authKey is already a key derivative — never the raw master password.
    """
    return pwd_context.hash(auth_key)


def verify_auth_key(plain_auth_key: str, hashed_auth_key: str) -> bool:
    """
    Verifies a login attempt by comparing the submitted authKey
    against the stored bcrypt hash.
    """
    return pwd_context.verify(plain_auth_key, hashed_auth_key)


# ---------------------------------------------------------------------------
# Vault Entry Validation
# ---------------------------------------------------------------------------

def validate_vault_entry(password: bytes, iv: bytes, salt: bytes) -> bool:
    """
    Validates that vault entry fields are well-formed before storing.
    Does NOT decrypt — just checks the data is the right shape.
    """
    if len(iv) != 12:       # AES-GCM requires a 96-bit (12-byte) nonce
        return False
    if len(salt) != 16:     # 128-bit salt minimum
        return False
    if len(password) == 0:
        return False
    return True


# ---------------------------------------------------------------------------
# Session Cookie Helpers
# ---------------------------------------------------------------------------

def _sign(data: str) -> str:
    """HMAC-SHA256 signature using the session secret."""
    return hmac.new(
        SESSION_SECRET.encode(),
        data.encode(),
        hashlib.sha256,
    ).hexdigest()


def create_session_token(user_id: int) -> str:
    """
    Creates a signed session token storing user_id and expiry.
    Format: base64(payload) + "." + hmac_signature
    """
    payload = json.dumps({
        "user_id": user_id,
        "expires": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
    })
    encoded = base64.b64encode(payload.encode()).decode()
    return f"{encoded}.{_sign(encoded)}"


def verify_session_token(token: str) -> int | None:
    """
    Verifies a session token and returns the user_id if valid.
    Returns None if the token is missing, tampered with, or expired.
    """
    try:
        encoded, signature = token.rsplit(".", 1)
    except ValueError:
        return None

    # Constant-time comparison prevents timing attacks
    if not hmac.compare_digest(_sign(encoded), signature):
        return None
    
    # Reject if token has been explicitly revoked
    if is_token_revoked(token):
        return None

    payload = json.loads(base64.b64decode(encoded).decode())

    if datetime.utcnow() > datetime.fromisoformat(payload["expires"]):
        return None

    return payload["user_id"]

# ---------------------------------------------------------------------------
# Token Denylist (in-memory — clears on server restart)
# ---------------------------------------------------------------------------

_revoked_tokens: set[str] = set()

def revoke_token(token: str) -> None:
    """Add a token signature to the denylist on logout."""
    try:
        _, signature = token.rsplit(".", 1)
        _revoked_tokens.add(signature)
    except ValueError:
        pass

def is_token_revoked(token: str) -> bool:
    """Returns True if the token has been explicitly logged out."""
    try:
        _, signature = token.rsplit(".", 1)
        return signature in _revoked_tokens
    except ValueError:
        return True
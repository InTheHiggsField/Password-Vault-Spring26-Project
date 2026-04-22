import os
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env file if present (development convenience)
# In production, set environment variables directly — never commit .env
# ---------------------------------------------------------------------------

load_dotenv()

# ---------------------------------------------------------------------------
# Required secrets — raise at startup if missing so failures are immediate
# and obvious rather than surfacing as cryptic runtime errors later
# ---------------------------------------------------------------------------

SESSION_SECRET: str = os.environ.get("SESSION_SECRET", "")

if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET environment variable is not set.\n"
        "Generate one with:\n"
        "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then add it to your .env file (never commit the .env file)."
    )
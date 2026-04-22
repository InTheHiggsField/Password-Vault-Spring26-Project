from fastapi import FastAPI, HTTPException, status, Depends, Response, Cookie, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_serializer, model_validator
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel, Field
import base64

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hmac
import hashlib

from backend.app.database import get_session, engine, Base
from backend.models.user import User as DBUser
from backend.models.vault_entry import VaultEntry as DBVaultEntry
from backend.core.security import (
    hash_auth_key,
    verify_auth_key,
    validate_vault_entry,
    create_session_token,
    verify_session_token,
    revoke_token, 
)
from backend.app.config import SESSION_SECRET

Base.metadata.create_all(bind=engine)

app = FastAPI()

# 1. Initialize the limiter to use the user's IP address
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS — allows the React dev server (localhost:3000) to talk to this API
# ---------------------------------------------------------------------------
origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class User(BaseModel):
    email: str = Field(..., max_length=255)
    username: str = Field(..., max_length=255)
    hashed_password: str = Field(..., max_length=128)
    salt: str = Field(None, max_length=32)


class VaultEntryIn(BaseModel):
    """
    Accepts base64-encoded strings from the frontend and decodes them to bytes.
    The frontend sends JSON with base64 strings — not raw bytes.
    """
    account: str = Field(..., max_length=255)
    password: str = Field(..., max_length=255)   # base64 ciphertext
    iv: str = Field(..., max_length=255)        # base64 IV
    salt: str = Field(..., max_length=255)      # base64 salt

    def decode_fields(self):
        """Returns decoded bytes for password, iv, and salt."""
        return (
            base64.b64decode(self.password),
            base64.b64decode(self.iv),
            base64.b64decode(self.salt),
        )


class VaultEntryResponse(BaseModel):
    id: int
    user_id: int
    account: str
    password: str   # returned as base64
    iv: str         # returned as base64
    salt: str       # returned as base64

    @classmethod
    def from_db(cls, entry: DBVaultEntry) -> "VaultEntryResponse":
        return cls(
            id=entry.id,
            user_id=entry.user_id,
            account=entry.account,
            password=base64.b64encode(entry.password).decode('utf-8'),
            iv=base64.b64encode(entry.iv).decode('utf-8'),
            salt=base64.b64encode(entry.salt).decode('utf-8'),
        )

    class Config:
        from_attributes = True


class ChangePasswordRequest(BaseModel):
    current_hashed_password: str = Field(..., max_length=128)
    new_hashed_password: str = Field(..., max_length=128)
    new_salt: str = Field(..., max_length=32)


class DeleteAccountRequest(BaseModel):
    current_hashed_password: str = Field(..., max_length=128)


# ---------------------------------------------------------------------------
# DB dependency
# ---------------------------------------------------------------------------

def get_db():
    db = get_session()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Session cookie dependency — used by every vault route
# ---------------------------------------------------------------------------

def get_current_user_id(session_id: str = Cookie(None)) -> int:
    if not session_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    user_id = verify_session_token(session_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_salt_for(email: str) -> str:
    """
    Derives a deterministic but unpredictable 32-char hex salt for an email
    using HMAC-SHA256 keyed with SESSION_SECRET.

    Properties:
    - Same email always returns the same value (consistent)
    - Without SESSION_SECRET an attacker cannot predict it (unpredictable)
    - Indistinguishable from a real salt in length and format
    - Does NOT reveal whether the email is registered

    Used to prevent user enumeration via the /auth/get-salt endpoint.
    """
    digest = hmac.new(
        SESSION_SECRET.encode(),
        f"fake-salt:{email}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return digest[:32]  # 32 hex chars = 16 bytes, matching real salt format


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return {"message": "Password Vault API"}


@app.get("/grab-username")
def getUser(curr_user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    findUserName = db.query(DBUser).filter(DBUser.id == curr_user_id).first()
    if not findUserName:
        raise HTTPException(status_code=401, detail="Username not found")
    else:
        return {"message": "Username successfully retrieved", "username": findUserName.username}


@app.get("/auth/get-salt")
def get_user_salt(email: str, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if not user or not user.salt:
        return {"salt": _fake_salt_for(email)}
    return {"salt": user.salt}


@app.post("/auth/signup")
@limiter.limit("3/minute")
def create_user(request: Request, user_data: User, response: Response, db: Session = Depends(get_db)):
    existing = db.query(DBUser).filter(DBUser.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if db.query(DBUser).filter(DBUser.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    if not user_data.salt:
        raise HTTPException(
            status_code=422,
            detail="Salt is required. Frontend must generate and send a random 16-byte salt.",
        )

    if len(user_data.salt) != 32 or not all(c in "0123456789abcdefABCDEF" for c in user_data.salt):
        raise HTTPException(
            status_code=422,
            detail="Invalid salt format. Must be 32 hex characters (16 bytes).",
        )

    new_user = DBUser(
        email=user_data.email,
        username=user_data.username,
        password=hash_auth_key(user_data.hashed_password),
        salt=user_data.salt.lower(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_session_token(new_user.id)
    response.set_cookie(
        key="session_id",
        value=token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=28800,
    )

    return {"message": "User created", "user_id": new_user.id}


@app.post("/auth/login")
@limiter.limit("5/minute")
def verify_user(request: Request, user: User, response: Response, db: Session = Depends(get_db)):
    user_temp = db.query(DBUser).filter(DBUser.email == user.email).first()

    if not user_temp or not verify_auth_key(user.hashed_password, user_temp.password):
        print()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user_temp.salt:
        import secrets
        user_temp.salt = secrets.token_hex(16)
        db.commit()
        db.refresh(user_temp)

    token = create_session_token(user_temp.id)
    response.set_cookie(
        key="session_id",
        value=token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=28800,
    )

    return {"message": "Login successful", "user_id": user_temp.id, "username": user_temp.username}


@app.post("/auth/logout")
def logout(response: Response, session_id: str = Cookie(None)):
    if session_id:
        revoke_token(session_id)
    response.delete_cookie(
        key="session_id",
        httponly=True,
        samesite="strict",
        secure=False,
    )
    return {"message": "Logged out successfully"}


@app.put("/auth/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    body: ChangePasswordRequest,
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    user = db.query(DBUser).filter(DBUser.id == curr_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_auth_key(body.current_hashed_password, user.password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if len(body.new_salt) != 32 or not all(c in "0123456789abcdefABCDEF" for c in body.new_salt):
        raise HTTPException(
            status_code=422,
            detail="Invalid salt format. Must be 32 hex characters (16 bytes).",
        )

    user.password = hash_auth_key(body.new_hashed_password)
    user.salt = body.new_salt.lower()
    db.commit()

    return {"message": "Password updated successfully"}


@app.delete("/auth/account")
@limiter.limit("3/minute")
def delete_account(
    request: Request,
    body: DeleteAccountRequest,
    response: Response,
    session_id: str = Cookie(None),
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    user = db.query(DBUser).filter(DBUser.id == curr_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_auth_key(body.current_hashed_password, user.password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Cascade delete on the FK handles vault entries automatically
    db.delete(user)
    db.commit()

    # Revoke session and clear cookie so the browser can't reuse it
    if session_id:
        revoke_token(session_id)
    response.delete_cookie(
        key="session_id",
        httponly=True,
        samesite="strict",
        secure=False,
    )

    return {"message": "Account deleted"}


# ---------------------------------------------------------------------------
# Vault routes — all protected by session cookie
# ---------------------------------------------------------------------------

@app.get("/vault", response_model=List[VaultEntryResponse])
def grab_vault(
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    entries = db.query(DBVaultEntry).filter(DBVaultEntry.user_id == curr_user_id).all()
    return [VaultEntryResponse.from_db(e) for e in entries]


@app.post("/vault", response_model=VaultEntryResponse)
def new_entry(
    entry: VaultEntryIn,
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    password_bytes, iv_bytes, salt_bytes = entry.decode_fields()

    if not validate_vault_entry(password_bytes, iv_bytes, salt_bytes):
        raise HTTPException(
            status_code=422,
            detail="Malformed encryption data — check IV (12 bytes) and salt (16 bytes) lengths.",
        )

    db_entry = DBVaultEntry(
        user_id=curr_user_id,
        account=entry.account,
        password=password_bytes,
        iv=iv_bytes,
        salt=salt_bytes,
    )
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)
    return VaultEntryResponse.from_db(db_entry)


@app.get("/vault/entry/{entry_id}", response_model=VaultEntryResponse)
def get_entry(
    entry_id: int,
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    entry = db.query(DBVaultEntry).filter(
        DBVaultEntry.id == entry_id,
        DBVaultEntry.user_id == curr_user_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return VaultEntryResponse.from_db(entry)


@app.put("/vault/entry/{entry_id}", response_model=VaultEntryResponse)
def update_entry(
    entry_id: int,
    updated_data: VaultEntryIn,
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    entry = db.query(DBVaultEntry).filter(
        DBVaultEntry.id == entry_id,
        DBVaultEntry.user_id == curr_user_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    password_bytes, iv_bytes, salt_bytes = updated_data.decode_fields()

    if not validate_vault_entry(password_bytes, iv_bytes, salt_bytes):
        raise HTTPException(
            status_code=422,
            detail="Malformed encryption data — check IV (12 bytes) and salt (16 bytes) lengths.",
        )

    entry.account = updated_data.account
    entry.password = password_bytes
    entry.iv = iv_bytes
    entry.salt = salt_bytes
    db.commit()
    db.refresh(entry)
    return VaultEntryResponse.from_db(entry)


@app.delete("/vault/entry/{entry_id}")
def delete_entry(
    entry_id: int,
    curr_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    entry = db.query(DBVaultEntry).filter(
        DBVaultEntry.id == entry_id,
        DBVaultEntry.user_id == curr_user_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    db.delete(entry)
    db.commit()
    return {"message": "Entry deleted"}
from backend.models import User, VaultEntry


# ---------------------------------------------------------------------------
# User functions
# ---------------------------------------------------------------------------

def get_user(session, **kwargs):
    """Search for a user by any model field (e.g. id=, email=, username=)."""
    return session.query(User).filter_by(**kwargs).first()


def add_user(session, email: str, username: str, password: str):
    """
    Creates a new user. Returns the existing user if email or username
    is already taken (caller should check the return value).
    password should be a bcrypt hash of the PBKDF2-derived authKey —
    never a raw password.
    """
    existing = get_user(session, username=username)
    if existing:
        print(f"User '{username}' already exists.")
        return existing

    existing = get_user(session, email=email)
    if existing:
        print(f"User with email '{email}' already exists.")
        return existing

    user = User(email=email, username=username, password=password)
    session.add(user)
    session.commit()
    session.refresh(user)   # ensures user.id is populated before returning
    return user


def print_user_vault_entries(session, **kwargs):
    """Print all vault entries for a user identified by any model field."""
    user = get_user(session, **kwargs)
    if not user:
        print("User not found.")
        return

    if not user.vault_entries:
        print(f"{user.username} has no vault entries.")
        return

    print(f"Vault entries for {user.username}:")
    for entry in user.vault_entries:
        print(f"  ID: {entry.id}, Account: {entry.account}")


def update_user(session, user, **kwargs):
    """Update user fields. Skips username/email if already taken by another user."""
    if "username" in kwargs:
        existing = get_user(session, username=kwargs["username"])
        if existing and existing.id != user.id:
            print(f"Username '{kwargs['username']}' already taken.")
            kwargs.pop("username")

    if "email" in kwargs:
        existing = get_user(session, email=kwargs["email"])
        if existing and existing.id != user.id:
            print(f"Email '{kwargs['email']}' already taken.")
            kwargs.pop("email")

    for key, value in kwargs.items():
        if hasattr(user, key):
            setattr(user, key, value)
        else:
            print(f"Warning: '{key}' is not a valid User field.")

    session.commit()
    return user


def delete_user(session, user, delete_vault_entries: bool = True):
    """Delete a user. Cascade-deletes vault entries by default."""
    if delete_vault_entries:
        for entry in list(user.vault_entries):
            session.delete(entry)
    session.delete(user)
    session.commit()


def get_all_users(session):
    return session.query(User).all()


def print_all_users(session):
    users = get_all_users(session)
    for u in users:
        print(f"ID: {u.id}, Username: {u.username}, Email: {u.email}, "
              f"Vault entries: {len(u.vault_entries)}")


# ---------------------------------------------------------------------------
# Vault entry functions
# ---------------------------------------------------------------------------

def add_vault_entry(
    session,
    user_id: int,
    account: str,
    password: bytes,
    iv: bytes = b"",
    salt: bytes = b"",
):
    """
    Adds a vault entry for a user.
    password, iv, and salt should be the AES-GCM encrypted values from the
    frontend — never plaintext. iv must be 12 bytes, salt must be 16 bytes.
    The defaults are empty bytes so callers that omit them get a clear
    validate_vault_entry failure rather than silently storing bad data.
    """
    entry = VaultEntry(
        user_id=user_id,
        account=account,
        password=password,
        iv=iv,
        salt=salt,
    )
    session.add(entry)
    session.commit()
    return entry


def get_vault_entries(session, user_id: int = None, user=None):
    """Return vault entries for a user, or all entries if no user specified."""
    if user:
        user_id = user.id
    if user_id is None:
        return session.query(VaultEntry).all()
    return session.query(VaultEntry).filter_by(user_id=user_id).all()


def update_vault_entry(session, entry, **kwargs):
    """Update arbitrary fields on a vault entry."""
    for key, value in kwargs.items():
        setattr(entry, key, value)
    session.commit()
    return entry


def delete_vault_entry(session, entry):
    session.delete(entry)
    session.commit()
# Password Vault

## Overview

A full-stack zero-knowledge password vault. The master password never reaches the server — PBKDF2 derives two keys client-side: an `authKey` (sent to the backend for login verification) and an `encryptionKey` (never leaves the browser, used to AES-GCM encrypt/decrypt vault entries). The backend stores only ciphertext it cannot read.

**Stack:** FastAPI · SQLite · SQLAlchemy 2.x · React · TypeScript

---

## Requirements

* Python **3.12.x (64-bit)**
* Node.js **18+**
* Git

---

## Backend Setup

### 1. Install Python 3.12

Download from [https://www.python.org/downloads/](https://www.python.org/downloads/)

Ensure **Add Python to PATH** is checked during installation. Verify:

```bash
py -0
```

### 2. Create Virtual Environment

```bash
py -3.12 -m venv venv --upgrade-deps
```

Activate:

**Windows**
```bash
venv\Scripts\activate
```

**macOS / Linux**
```bash
source venv/bin/activate
```

Verify:
```bash
python --version
python -m pip --version
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Create a `.env` file in the project root (never commit this):

```env
SESSION_SECRET=your_generated_secret_here
```

Generate a secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
KEY WILL BE SHARED ON DISCORD
A `.env.example` is committed to the repo with empty keys for reference.

### 5. Run the Backend

```bash
fastapi dev backend/api/auth.py
```

Or with uvicorn directly:

```bash
uvicorn backend.api.auth:app --reload
```

Default server:

* API: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* Interactive docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Frontend Setup

### 1. Install Dependencies

```bash
cd Password_Vault_Frontend
npm install
```

### 2. Run the Frontend

```bash
npm start
```

Default server: [http://localhost:3000](http://localhost:3000)

The React dev server proxies API requests to `http://localhost:8000`.

---

## Database

The project uses **SQLite**. The database file (`vault.db`) is created automatically in the project root on first run — no setup required.

To inspect the database directly:

```bash
sqlite3 vault.db
```

---

## Testing

```bash
pytest
```

---

## Project Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI |
| Server | Uvicorn |
| ORM | SQLAlchemy 2.x |
| Database | SQLite |
| Validation | Pydantic v2 |
| Auth | HMAC-SHA256 signed session cookies |
| Encryption | AES-GCM (client-side, Web Crypto API) |
| Key derivation | PBKDF2 · 100,000 iterations · SHA-256 |
| Frontend | React · TypeScript |
| HTTP client | HTTPX |
| Testing | Pytest |

---

## Troubleshooting

### pip not found

Recreate the virtual environment:

```bash
rmdir /s /q venv
py -3.12 -m venv venv --upgrade-deps
venv\Scripts\activate
```

### Dependency installation errors

Upgrade tooling, clear cache, and retry:

```bash
python -m pip install --upgrade pip setuptools wheel
pip cache purge
pip install -r requirements.txt
```

### SESSION_SECRET not set

The server will refuse to start with a clear error message. Generate a secret and add it to `.env` — see step 4 above.

### CORS errors in the browser

Ensure both servers are running: backend on port `8000` and frontend on port `3000`. The CORS middleware in `auth.py` allows `http://localhost:3000` by default.

---

## Notes

* Python 3.13 is not recommended due to incomplete package wheel support.
* Do not manually pin `pydantic-core`.
* `secure=False` is set on session cookies for local development. In production, serve over HTTPS and set `secure=True` in `auth.py`.
* The `SESSION_SECRET` should be shared between team members out-of-band (e.g. a private channel) and never committed to version control.
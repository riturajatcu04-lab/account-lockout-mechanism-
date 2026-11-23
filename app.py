import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.getenv("DATABASE_PATH", "instance/account_lockout.db"))
if not DATABASE.is_absolute():
    DATABASE = ROOT / DATABASE
DATABASE.parent.mkdir(parents=True, exist_ok=True)

MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "30"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

def now_ts():
    return int(datetime.now(timezone.utc).timestamp())

def utc_text(timestamp=None):
    if timestamp is None:
        timestamp = now_ts()
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        event TEXT NOT NULL,
        ip_address TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    );
    """)
    db.commit()

    # Create the administrator once, using environment variables.
    if ADMIN_PASSWORD:
        row = db.execute(
            "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
        ).fetchone()
        if row is None:
            db.execute(
                """INSERT INTO users
                   (username, password_hash, role, created_at)
                   VALUES (?, ?, 'admin', ?)""",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), utc_text()),
            )
            db.commit()
    db.close()

def audit(username, event, details=""):
    db = get_db()
    db.execute(
        """INSERT INTO audit_logs
           (username, event, ip_address, details, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (username, event, request.remote_addr or "unknown", details[:250], utc_text()),
    )
    db.commit()

def api_error(message, status=400):
    return jsonify({"ok": False, "message": message}), status

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return api_error("Please log in first.", 401)
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return api_error("Please log in first.", 401)
        if session.get("role") != "admin":
            return api_error("Administrator access required.", 403)
        return fn(*args, **kwargs)
    return wrapper

@app.get("/api/csrf")
@limiter.limit("30 per minute")
def csrf_token():
    return jsonify({"csrfToken": generate_csrf()})

@app.post("/api/register")
@limiter.limit("3 per minute")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not (3 <= len(username) <= 30) or not username.replace("_", "").isalnum():
        return api_error("Username must be 3–30 characters (letters, numbers or underscore).")
    if len(password) < 12:
        return api_error("Password must contain at least 12 characters.")

    db = get_db()
    try:
        db.execute(
            """INSERT INTO users (username, password_hash, role, created_at)
               VALUES (?, ?, 'user', ?)""",
            (username, generate_password_hash(password), utc_text()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return api_error("That username is already registered.", 409)

    audit(username, "REGISTER_SUCCESS", "New account created")
    return jsonify({"ok": True, "message": "Registration successful. You can now log in."}), 201

@app.post("/api/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return api_error("Enter both username and password.")

    db = get_db()
    # A write transaction makes the counter update safer when requests overlap.
    db.execute("BEGIN IMMEDIATE")
    user = db.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()

    # Use a generic response so the endpoint does not reveal whether a username exists.
    if user is None:
        db.commit()
        audit(username, "LOGIN_FAILED", "Invalid credentials")
        return api_error("Invalid username or password.", 401)

    current = now_ts()
    if user["locked_until"] and user["locked_until"] > current:
        remaining = user["locked_until"] - current
        db.commit()
        audit(user["username"], "LOGIN_BLOCKED", f"Account locked; {remaining}s remain")
        return jsonify({
            "ok": False,
            "locked": True,
            "remainingSeconds": remaining,
            "message": f"Account temporarily locked. Try again in {remaining} seconds."
        }), 423

    # Expired lock: clear lock and reset the counter before checking credentials.
    if user["locked_until"] and user["locked_until"] <= current:
        db.execute(
            "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
            (user["id"],),
        )
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    if check_password_hash(user["password_hash"], password):
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        db.commit()
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        audit(user["username"], "LOGIN_SUCCESS", "Credentials verified")
        return jsonify({
            "ok": True,
            "message": "Login successful.",
            "user": {"username": user["username"], "role": user["role"]}
        })

    attempts = user["failed_attempts"] + 1
    if attempts >= MAX_ATTEMPTS:
        until = current + LOCKOUT_SECONDS
        db.execute(
            """UPDATE users SET failed_attempts = ?, locked_until = ?
               WHERE id = ?""",
            (attempts, until, user["id"]),
        )
        db.commit()
        audit(user["username"], "ACCOUNT_LOCKED", f"Locked for {LOCKOUT_SECONDS} seconds")
        return jsonify({
            "ok": False,
            "locked": True,
            "remainingSeconds": LOCKOUT_SECONDS,
            "message": f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS} seconds."
        }), 423

    db.execute(
        "UPDATE users SET failed_attempts = ? WHERE id = ?",
        (attempts, user["id"]),
    )
    db.commit()
    audit(user["username"], "LOGIN_FAILED", f"Failed attempt {attempts} of {MAX_ATTEMPTS}")
    return jsonify({
        "ok": False,
        "remainingAttempts": MAX_ATTEMPTS - attempts,
        "message": "Invalid username or password."
    }), 401

@app.get("/api/me")
@login_required
def me():
    return jsonify({
        "ok": True,
        "user": {"username": session["username"], "role": session["role"]}
    })

@app.post("/api/logout")
@login_required
def logout():
    username = session.get("username", "unknown")
    session.clear()
    audit(username, "LOGOUT", "User logged out")
    return jsonify({"ok": True, "message": "Logged out."})

@app.get("/api/admin/summary")
@admin_required
def admin_summary():
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    locked_count = db.execute(
        "SELECT COUNT(*) AS n FROM users WHERE locked_until > ?", (now_ts(),)
    ).fetchone()["n"]
    logs = db.execute(
        """SELECT username, event, ip_address, details, created_at
           FROM audit_logs ORDER BY id DESC LIMIT 100"""
    ).fetchall()
    return jsonify({
        "ok": True,
        "userCount": user_count,
        "lockedCount": locked_count,
        "logs": [dict(row) for row in logs]
    })

@app.get("/api/admin/users")
@admin_required
def admin_users():
    db = get_db()
    current = now_ts()
    users = db.execute(
        """SELECT username, role, failed_attempts, locked_until, created_at
           FROM users ORDER BY created_at DESC, id DESC"""
    ).fetchall()
    return jsonify({
        "ok": True,
        "users": [
            {
                "username": user["username"],
                "role": user["role"],
                "failedAttempts": user["failed_attempts"],
                "locked": user["locked_until"] is not None and user["locked_until"] > current,
                "lockExpiresAt": (
                    utc_text(user["locked_until"])
                    if user["locked_until"] is not None and user["locked_until"] > current
                    else None
                ),
                "createdAt": user["created_at"],
            }
            for user in users
        ],
    })

@app.errorhandler(429)
def rate_limit_error(_error):
    return jsonify({"ok": False, "message": "Too many requests. Please slow down."}), 429

@app.errorhandler(400)
def bad_request(_error):
    return jsonify({"ok": False, "message": "Invalid request or missing CSRF token."}), 400

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "Account Lockout API"})

init_db()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=True)

from flask import jsonify, request
from functools import wraps
import jwt
import datetime
import os
import time
from collections import defaultdict

from database import execute_query, verify_password

# ======================================================
# CONFIG
# ======================================================

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

# Login rate-limit / brute-force protection
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))     # 15 minutes
LOGIN_BLOCK_MINUTES = int(os.getenv("LOGIN_BLOCK_MINUTES", "15"))       # 15 minutes

# key: (client_ip, username_lower) -> dict(count, first_ts, blocked_until)
_login_tracker = defaultdict(lambda: {
    "count": 0,
    "first_ts": 0.0,
    "blocked_until": 0.0,
})


# ======================================================
# HELPERS
# ======================================================

def _now() -> float:
    return time.time()


def _get_client_ip() -> str:
    """
    Best effort IP extraction.
    In prod behind reverse proxy, ensure X-Forwarded-For is trusted.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # "client, proxy1, proxy2"
        return xff.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.remote_addr or "0.0.0.0"


def _get_login_key(ip: str, username: str | None) -> tuple[str, str]:
    uname = (username or "").strip().lower()
    return ip, uname


def _is_blocked(key: tuple[str, str]) -> bool:
    rec = _login_tracker.get(key)
    if not rec:
        return False
    return rec["blocked_until"] > _now()


def _register_failed_attempt(key: tuple[str, str]) -> dict:
    """
    Update tracker on failed login.
    Returns record dict (for debug/logging if needed).
    """
    now = _now()
    rec = _login_tracker[key]

    # Reset window if sudah lewat
    if rec["first_ts"] == 0.0 or (now - rec["first_ts"]) > LOGIN_WINDOW_SECONDS:
        rec["count"] = 0
        rec["first_ts"] = now
        rec["blocked_until"] = 0.0

    rec["count"] += 1

    if rec["count"] >= LOGIN_MAX_ATTEMPTS:
        # block for LOGIN_BLOCK_MINUTES
        rec["blocked_until"] = now + LOGIN_BLOCK_MINUTES * 60
        # reset counter (next window)
        rec["count"] = 0
        rec["first_ts"] = now

    return rec


def _reset_login_key(key: tuple[str, str]) -> None:
    if key in _login_tracker:
        del _login_tracker[key]


# ======================================================
# JWT UTIL
# ======================================================

def generate_token(user_id: int, username: str, is_admin: bool = False) -> str:
    now = datetime.datetime.utcnow()

    payload = {
        "sub": str(user_id),
        "user_id": user_id,
        "username": username,
        "is_admin": bool(is_admin),
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return token if isinstance(token, str) else token.decode()


def verify_token(token: str):
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["exp", "iat", "nbf"],
                "verify_signature": True,
                "verify_exp": True,
            },
        )
    except jwt.InvalidTokenError:
        return None


# ======================================================
# AUTH DECORATOR
# ======================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth.split(" ", 1)[1].strip()
        payload = verify_token(token)

        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(payload, *args, **kwargs)

    return decorated


# ======================================================
# AUTH ROUTES
# ======================================================

def init_auth_routes(app):

    # ---------------- LOGIN ----------------
    @app.route("/api/login", methods=["POST"])
    def api_login():
        """
        Secure login:
        - bcrypt password check (via verify_password)
        - no username enumeration (generic 'Invalid credentials')
        - IP + username based brute-force protection
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            # Generic message, no hint
            return jsonify({"error": "Invalid credentials"}), 401

        client_ip = _get_client_ip()
        key = _get_login_key(client_ip, username)

        # 1) Check if blocked
        if _is_blocked(key):
            return jsonify({
                "error": "Too many login attempts. Please try again later."
            }), 429

        try:
            # 2) Fetch user row (by username only)
            rows = execute_query(
                """
                SELECT id, username, password_hash, is_admin
                FROM users
                WHERE username = %s
                """,
                (username,),
            )

            if not rows:
                # Register failed attempt and generic error
                _register_failed_attempt(key)
                return jsonify({"error": "Invalid credentials"}), 401

            user_id, db_username, password_hash, is_admin = rows[0]

            # 3) Verify password via bcrypt
            if not verify_password(password, password_hash):
                _register_failed_attempt(key)
                return jsonify({"error": "Invalid credentials"}), 401

            # 4) Success -> reset tracker
            _reset_login_key(key)

            token = generate_token(
                user_id=user_id,
                username=db_username,
                is_admin=is_admin,
            )

            return jsonify({
                "status": "success",
                "token": token,
                "expires_in_minutes": ACCESS_TOKEN_MINUTES,
            })

        except Exception:
            # NOTE: sengaja generic, jangan bocorin detail DB
            return jsonify({"error": "Authentication failed"}), 500

    # ---------------- BALANCE ----------------
    @app.route("/api/check_balance", methods=["GET"])
    @token_required
    def api_check_balance(current_user):
        """
        BOLA-safe:
        - user hanya bisa lihat saldo miliknya sendiri
        """
        try:
            rows = execute_query(
                """
                SELECT username, balance, account_number
                FROM users
                WHERE id = %s
                """,
                (current_user["user_id"],),
            )

            if not rows:
                return jsonify({"error": "Account not found"}), 404

            username, balance, account_number = rows[0]

            return jsonify({
                "username": username,
                "balance": float(balance),
                "account_number": account_number,
            })

        except Exception:
            return jsonify({"error": "Failed to fetch balance"}), 500

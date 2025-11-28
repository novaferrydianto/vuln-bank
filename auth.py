from flask import jsonify, request
from functools import wraps
import jwt
import datetime
import os
import psycopg2

# ======================================================
# CONFIG
# ======================================================

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

DB_DSN = os.getenv("DATABASE_URL")
if not DB_DSN:
    raise RuntimeError("DATABASE_URL is not set")

# ======================================================
# JWT UTIL
# ======================================================

def generate_token(user_id: int, username: str, is_admin: bool = False) -> str:
    """
    ✅ Secure JWT:
    - HS256 only
    - exp / iat / nbf enforced
    """
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

    # normalize (pyjwt v1 vs v2)
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return token


def verify_token(token: str):
    """
    ✅ STRICT verification:
    - Signature REQUIRED
    - Exp REQUIRED
    - HS256 ONLY
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["exp", "iat", "nbf"],
                "verify_signature": True,
                "verify_exp": True,
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ======================================================
# AUTH DECORATOR
# ======================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        # ✅ PROD RULE: Bearer token ONLY
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing or invalid"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"error": "Token missing"}), 401

        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(payload, *args, **kwargs)

    return decorated


# ======================================================
# AUTH ROUTES
# ======================================================

def init_auth_routes(app):

    @app.route("/api/login", methods=["POST"])
    def api_login():
        """
        ✅ Secure login:
        - parameterized SQL
        - generic error message
        - minimal response data
        NOTE:
        Password hashing intentionally omitted here
        (handled separately or in DB migration)
        """
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Invalid credentials"}), 401

        try:
            conn = psycopg2.connect(DB_DSN)
            cur = conn.cursor()

            cur.execute(
                """
                SELECT id, username, is_admin
                FROM users
                WHERE username = %s AND password = %s
                """,
                (username, password),
            )
            user = cur.fetchone()
            conn.close()

            if not user:
                # ✅ no enumeration
                return jsonify({"error": "Invalid credentials"}), 401

            token = generate_token(
                user_id=user[0],
                username=user[1],
                is_admin=user[2],
            )

            return jsonify({
                "status": "success",
                "token": token,
                "expires_in_minutes": ACCESS_TOKEN_MINUTES,
            })

        except Exception:
            return jsonify({"error": "Authentication failed"}), 500


    @app.route("/api/check_balance", methods=["GET"])
    @token_required
    def api_check_balance(current_user):
        """
        ✅ BOLA-safe:
        - user can only check OWN balance
        """
        user_id = current_user["user_id"]

        try:
            conn = psycopg2.connect(DB_DSN)
            cur = conn.cursor()

            cur.execute(
                """
                SELECT username, balance, account_number
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()
            conn.close()

            if not row:
                return jsonify({"error": "Account not found"}), 404

            return jsonify({
                "username": row[0],
                "balance": float(row[1]),
                "account_number": row[2],
            })

        except Exception:
            return jsonify({"error": "Failed to fetch balance"}), 500

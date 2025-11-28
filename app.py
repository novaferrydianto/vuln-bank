from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from datetime import datetime, timedelta
import random
import string
import os
import secrets
import uuid
import logging
import time

from dotenv import load_dotenv
from auth import generate_token, token_required, init_auth_routes
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from database import (
    init_connection_pool,
    init_db,
    execute_query,
    get_connection,
    return_connection,
)
from functools import wraps
from collections import defaultdict
import requests
from urllib.parse import urlparse

# =========================================================
# APP & CONFIG
# =========================================================

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

init_connection_pool()

# =========================================================
# SWAGGER
# =========================================================

SWAGGER_URL = "/api/docs"
API_URL = "/static/openapi.json"

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={"app_name": "Vuln Bank API", "validatorUrl": None},
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# =========================================================
# RATE LIMIT LOGIN
# =========================================================

login_attempts = defaultdict(list)

def rate_limit(limit=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]
            if len(login_attempts[ip]) >= limit:
                return jsonify({"error": "Too many login attempts"}), 429
            login_attempts[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# =========================================================
# HELPERS
# =========================================================

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_account_number():
    return "".join(random.choices(string.digits, k=10))

def generate_card_number():
    return "".join(secrets.choice(string.digits) for _ in range(16))

def generate_cvv():
    return "".join(secrets.choice(string.digits) for _ in range(3))

# =========================================================
# BASIC ROUTES
# =========================================================

@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.set_cookie("csrf_token", secrets.token_urlsafe(32), samesite="Lax")
    return resp

# =========================================================
# AUTH
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing fields"}), 400

        if execute_query("SELECT id FROM users WHERE username=%s", (username,)):
            return jsonify({"error": "Username already exists"}), 400

        hashed = generate_password_hash(password)
        account_number = generate_account_number()

        execute_query(
            "INSERT INTO users (username, password, account_number) VALUES (%s,%s,%s)",
            (username, hashed, account_number),
            fetch=False,
        )

        return jsonify({"status": "success"}), 201

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@rate_limit()
def login():
    if request.method == "POST":
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        rows = execute_query(
            "SELECT id, username, password, is_admin FROM users WHERE username=%s",
            (username,),
        )

        if not rows or not check_password_hash(rows[0][2], password):
            return jsonify({"error": "Invalid username or password"}), 401

        user = rows[0]
        token = generate_token(user[0], user[1], user[3])

        resp = make_response(jsonify({"status": "success"}))
        resp.set_cookie("token", token, httponly=True, secure=True, samesite="Lax")
        return resp

    return render_template("login.html")

# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@token_required
def dashboard(current_user):
    user = execute_query(
        "SELECT id, username, balance, account_number, is_admin FROM users WHERE id=%s",
        (current_user["user_id"],),
    )[0]

    loans = execute_query(
        "SELECT id, amount, status FROM loans WHERE user_id=%s",
        (current_user["user_id"],),
    )

    return render_template(
        "dashboard.html",
        username=user[1],
        balance=float(user[2]),
        account_number=user[3],
        loans=loans,
        is_admin=user[4],
    )

# =========================================================
# FORGOT & RESET PASSWORD
# =========================================================

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    username = data.get("username")

    rows = execute_query("SELECT id FROM users WHERE username=%s", (username,))
    if rows:
        pin = "".join(secrets.choice(string.digits) for _ in range(6))
        expires = datetime.utcnow() + timedelta(minutes=10)

        execute_query(
            "UPDATE users SET reset_pin=%s, reset_pin_expires=%s WHERE username=%s",
            (pin, expires, username),
            fetch=False,
        )

    return jsonify({"status": "success"})


@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    username = data.get("username")
    reset_pin = data.get("reset_pin")
    new_password = data.get("new_password")

    rows = execute_query(
        """
        SELECT id FROM users
        WHERE username=%s AND reset_pin=%s AND reset_pin_expires > NOW()
        """,
        (username, reset_pin),
    )

    if not rows:
        return jsonify({"error": "Invalid or expired PIN"}), 400

    hashed = generate_password_hash(new_password)

    execute_query(
        """
        UPDATE users
        SET password=%s, reset_pin=NULL, reset_pin_expires=NULL
        WHERE username=%s
        """,
        (hashed, username),
        fetch=False,
    )

    return jsonify({"status": "success"})

# =========================================================
# MONEY TRANSFER (ATOMIC)
# =========================================================

@app.route("/transfer", methods=["POST"])
@token_required
def transfer(current_user):
    data = request.get_json() or {}
    to_account = data.get("to_account")
    amount = float(data.get("amount", 0))

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT account_number, balance FROM users WHERE id=%s FOR UPDATE",
                (current_user["user_id"],),
            )
            sender_account, sender_balance = cur.fetchone()

            if sender_balance < amount:
                return jsonify({"error": "Insufficient balance"}), 400

            cur.execute(
                "UPDATE users SET balance = balance - %s WHERE id=%s",
                (amount, current_user["user_id"]),
            )
            cur.execute(
                "UPDATE users SET balance = balance + %s WHERE account_number=%s",
                (amount, to_account),
            )
            cur.execute(
                """
                INSERT INTO transactions (from_account, to_account, amount, transaction_type)
                VALUES (%s,%s,%s,'transfer')
                """,
                (sender_account, to_account, amount),
            )

        conn.commit()
        return jsonify({"status": "success"})

    except Exception as e:
<<<<<<< HEAD
        conn.rollback()
        logging.error(e)
        return jsonify({"error": "Transfer failed"}), 500
    finally:
        return_connection(conn)
=======
        print(f"Bill payment outer error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/bill-payments/history", methods=["GET"])
@token_required
def get_payment_history(current_user):
    try:
        query = """
            SELECT 
                bp.id,
                bp.amount,
                bp.payment_method,
                bp.reference_number,
                bp.status,
                bp.created_at,
                bp.processed_at,
                bp.description,
                b.name AS biller_name,
                bc.name AS category_name,
                vc.card_number
            FROM bill_payments bp
            JOIN billers b ON bp.biller_id = b.id
            JOIN bill_categories bc ON b.category_id = bc.id
            LEFT JOIN virtual_cards vc ON bp.card_id = vc.id
            WHERE bp.user_id = %s
            ORDER BY bp.created_at DESC
        """
        payments = execute_query(query, (current_user["user_id"],))

        return jsonify(
            {
                "status": "success",
                "payments": [
                    {
                        "id": p[0],
                        "amount": float(p[1]),
                        "payment_method": p[2],
                        "reference": p[3],
                        "status": p[4],
                        "created_at": str(p[5]),
                        "processed_at": str(p[6]) if p[6] else None,
                        "description": p[7],
                        "biller_name": p[8],
                        "category_name": p[9],
                        "card_last4": p[10][-4:] if p[10] else None,
                    }
                    for p in payments
                ],
            }
        )
    except Exception as e:
        print(f"Payment history error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


# =========================================================
# VIRTUAL CARDS
# =========================================================

@app.route("/api/virtual-cards/create", methods=["POST"])
@token_required
def create_virtual_card(current_user):
    try:
        data = request.get_json() or {}

        try:
            card_limit = float(data.get("card_limit", 1000.0))
            if card_limit <= 0:
                raise ValueError
        except Exception:
            return jsonify({"status": "error", "message": "Invalid card_limit"}), 400

        card_type = data.get("card_type", "standard")

        card_number = generate_card_number()
        cvv = generate_cvv()
        expiry_date = (datetime.now() + timedelta(days=365)).strftime("%m/%y")

        query = """
            INSERT INTO virtual_cards 
            (user_id, card_number, cvv, expiry_date, card_limit)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """
        params = (
            current_user["user_id"],
            card_number,
            cvv,
            expiry_date,
            card_limit,
        )

        result = execute_query(query, params)

        if not result:
            return jsonify(
                {"status": "error", "message": "Failed to create virtual card"}
            ), 500

        return jsonify(
            {
                "status": "success",
                "message": "Virtual card created",
                "card": {
                    "last4": card_number[-4:],
                    "expiry_date": expiry_date,
                    "limit": card_limit,
                    "type": card_type,
                },
            }
        )

    except Exception as e:
        print(f"Create virtual card error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/virtual-cards", methods=["GET"])
@token_required
def get_virtual_cards(current_user):
    try:
        query = """
            SELECT id, card_number, expiry_date, card_limit, current_balance,
                   is_frozen, is_active, created_at, last_used_at, card_type
            FROM virtual_cards 
            WHERE user_id = %s
        """
        cards = execute_query(query, (current_user["user_id"],))

        return jsonify(
            {
                "status": "success",
                "cards": [
                    {
                        "id": c[0],
                        "last4": c[1][-4:],
                        "expiry_date": c[2],
                        "limit": float(c[3]),
                        "balance": float(c[4]),
                        "is_frozen": c[5],
                        "is_active": c[6],
                        "created_at": str(c[7]),
                        "last_used_at": str(c[8]) if c[8] else None,
                        "card_type": c[9],
                    }
                    for c in cards
                ],
            }
        )
    except Exception as e:
        print(f"Get virtual cards error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/virtual-cards/<int:card_id>/toggle-freeze", methods=["POST"])
@token_required
def toggle_card_freeze(current_user, card_id):
    try:
        query = """
            UPDATE virtual_cards 
            SET is_frozen = NOT is_frozen 
            WHERE id = %s AND user_id = %s
            RETURNING is_frozen
        """
        result = execute_query(query, (card_id, current_user["user_id"]))

        if not result:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Card not found or access denied",
                    }
                ),
                404,
            )

        is_frozen = result[0][0]
        return jsonify(
            {
                "status": "success",
                "message": "Card frozen" if is_frozen else "Card unfrozen",
            }
        )

    except Exception as e:
        print(f"Toggle freeze error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/virtual-cards/<int:card_id>/transactions", methods=["GET"])
@token_required
def get_card_transactions(current_user, card_id):
    try:
        query = """
            SELECT ct.id,
                   ct.amount,
                   ct.merchant_name,
                   ct.transaction_type,
                   ct.status,
                   ct.timestamp,
                   ct.description
            FROM card_transactions ct
            JOIN virtual_cards vc ON ct.card_id = vc.id
            WHERE ct.card_id = %s AND vc.user_id = %s
            ORDER BY ct.timestamp DESC
        """
        txs = execute_query(query, (card_id, current_user["user_id"]))

        return jsonify(
            {
                "status": "success",
                "transactions": [
                    {
                        "id": t[0],
                        "amount": float(t[1]),
                        "merchant": t[2],
                        "type": t[3],
                        "status": t[4],
                        "timestamp": str(t[5]),
                        "description": t[6],
                    }
                    for t in txs
                ],
            }
        )
    except Exception as e:
        print(f"Card tx error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/virtual-cards/<int:card_id>/update-limit", methods=["POST"])
@token_required
def update_card_limit(current_user, card_id):
    try:
        data = request.get_json() or {}

        # Safe allowed fields mapping
        field_map = {
            "card_limit": "card_limit",
            "card_type": "card_type",
            "is_frozen": "is_frozen",
            "is_active": "is_active",
        }
        update_fields = []
        update_values = []

        for key, value in data.items():
            if key not in field_map:
                continue

            if key == "card_limit":
                try:
                    value = float(value)
                    if value <= 0:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "card_limit must be positive",
                                }
                            ),
                            400,
                        )
                except Exception:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Invalid card_limit",
                            }
                        ),
                        400,
                    )
            # Always use safe mapped column name, not raw user input
            update_fields.append(f"{field_map[key]} = %s")
            update_values.append(value)

        if not update_fields:
            return jsonify({"status": "error", "message": "No valid fields given"}), 400

        query = f"""
            UPDATE virtual_cards
            SET {', '.join(update_fields)}
            WHERE id = %s AND user_id = %s
            RETURNING id, card_limit, current_balance, is_frozen, is_active, card_type
        """
        update_values.append(card_id)
        update_values.append(current_user["user_id"])

        result = execute_query(query, tuple(update_values))

        if not result:
            return (
                jsonify(
                    {"status": "error", "message": "Card not found or access denied"}
                ),
                404,
            )

        row = result[0]
        return jsonify(
            {
                "status": "success",
                "message": "Card updated",
                "card": {
                    "id": row[0],
                    "card_limit": float(row[1]),
                    "current_balance": float(row[2]),
                    "is_frozen": row[3],
                    "is_active": row[4],
                    "card_type": row[5],
                },
            }
        )

    except Exception as e:
        print(f"Update card limit error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500

>>>>>>> 539ab45d1e6ac214ada45b0c5f207403c82fc4f9

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    init_db()
    init_auth_routes(app)
    app.run(host="0.0.0.0", port=5000, debug=False)

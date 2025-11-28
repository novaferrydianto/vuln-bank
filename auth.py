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
        conn.rollback()
        logging.error(e)
        return jsonify({"error": "Transfer failed"}), 500
    finally:
        return_connection(conn)

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    init_db()
    init_auth_routes(app)
    app.run(host="0.0.0.0", port=5000, debug=False)

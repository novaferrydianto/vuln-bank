from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from datetime import datetime, timedelta
import random
import string
import html
import os
import secrets
import uuid

from dotenv import load_dotenv
from auth import generate_token, token_required, verify_token, init_auth_routes
from werkzeug.utils import secure_filename
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from database import (
    init_connection_pool,
    init_db,
    execute_query,
    execute_transaction,
    get_connection,
    return_connection,
)
import time
from functools import wraps
from collections import defaultdict
import requests
from urllib.parse import urlparse

# =========================================================
# APP & CONFIG
# =========================================================

load_dotenv()

app = Flask(__name__)
CORS(app)

# Stronger secret key (use env or fallback)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# Limit upload size (2 MB)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Initialize DB pool
init_connection_pool()

SWAGGER_URL = "/api/docs"
API_URL = "/static/openapi.json"

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        "app_name": "Vuln Bank API (Prod Mode)",
        "validatorUrl": None,
    },
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# =========================================================
# FILE UPLOAD CONFIG
# =========================================================

UPLOAD_FOLDER = "static/uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_account_number():
    # 10-digit numeric account number
    return "".join(random.choices(string.digits, k=10))


def generate_card_number():
    # Use cryptographically secure random
    return "".join(secrets.choice(string.digits) for _ in range(16))


def generate_cvv():
    return "".join(secrets.choice(string.digits) for _ in range(3))


# =========================================================
# BASIC ROUTES
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            # Expect JSON body in API mode
            user_data = request.get_json() or {}

            username = user_data.get("username")
            password = user_data.get("password")

            if not username or not password:
                return jsonify(
                    {"status": "error", "message": "Username and password are required"}
                ), 400

            # Check username existence
            existing_user = execute_query(
                "SELECT username FROM users WHERE username = %s",
                (username,),
            )

            if existing_user:
                # No detailed debug info in prod
                return jsonify(
                    {
                        "status": "error",
                        "message": "Username already exists",
                    }
                ), 400

            account_number = generate_account_number()

            # Only allow safe fields
            fields = ["username", "password", "account_number"]
            values = [username, password, account_number]

            query = """
                INSERT INTO users (username, password, account_number)
                VALUES (%s, %s, %s)
                RETURNING id, username, account_number, balance, is_admin
            """
            result = execute_query(query, values, fetch=True)

            if not result or not result[0]:
                raise Exception("Failed to create user")

            return jsonify(
                {
                    "status": "success",
                    "message": "Registration successful, please login",
                }
            ), 201

        except Exception as e:
            print(f"Registration error: {str(e)}")
            return jsonify(
                {
                    "status": "error",
                    "message": "Registration failed",
                }
            ), 500

    # Fallback to HTML form
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            data = request.get_json() or {}
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return jsonify(
                    {"status": "error", "message": "Username and password required"}
                ), 400

            query = "SELECT * FROM users WHERE username=%s AND password=%s"
            params = (username, password)

            users = execute_query(query, params)
            if users and len(users) > 0:
                user = users[0]

                token = generate_token(user[0], user[1], user[5])

                response = make_response(
                    jsonify(
                        {
                            "status": "success",
                            "message": "Login successful",
                            "token": token,
                        }
                    )
                )
                # Secure cookie
                response.set_cookie(
                    "token",
                    token,
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                )
                return response

            # Generic error, no username enumeration
            return jsonify(
                {"status": "error", "message": "Invalid username or password"}
            ), 401

        except Exception as e:
            print(f"Login error: {str(e)}")
            return jsonify(
                {"status": "error", "message": "Login failed"}
            ), 500

    return render_template("login.html")


# =========================================================
# DASHBOARD & ACCOUNTS
# =========================================================

@app.route("/dashboard")
@token_required
def dashboard(current_user):
    # Get user by id (only self)
    user_rows = execute_query(
        "SELECT id, username, account_number, balance, is_admin, profile_picture "
        "FROM users WHERE id = %s",
        (current_user["user_id"],),
    )
    if not user_rows:
        return redirect(url_for("login"))

    user = user_rows[0]
    loans = execute_query(
        "SELECT id, amount, status FROM loans WHERE user_id = %s",
        (current_user["user_id"],),
    )

    user_data = {
        "id": user[0],
        "username": user[1],
        "account_number": user[2],
        "balance": float(user[3]),
        "is_admin": user[4],
        "profile_picture": user[5] or "user.png",
    }

    return render_template(
        "dashboard.html",
        user=user_data,
        username=user[1],
        balance=float(user[3]),
        account_number=user[2],
        loans=loans,
        is_admin=user[4],
    )


@app.route("/check_balance/<account_number>")
@token_required
def check_balance(current_user, account_number):
    """
    Secure: only allow checking own account balance.
    """
    try:
        rows = execute_query(
            """
            SELECT id, username, balance, account_number
            FROM users
            WHERE id = %s AND account_number = %s
            """,
            (current_user["user_id"], account_number),
        )

        if not rows:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Account not found or access denied",
                    }
                ),
                403,
            )

        u = rows[0]
        return jsonify(
            {
                "status": "success",
                "username": u[1],
                "balance": float(u[2]),
                "account_number": u[3],
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": "Internal error"}), 500


# =========================================================
# TRANSFER (MONEY-SAFE, ATOMIC)
# =========================================================

@app.route("/transfer", methods=["POST"])
@token_required
def transfer(current_user):
    """
    Secure money transfer:
    - Validates amount > 0
    - Uses DB transaction with row-level locks
    - Ensures sender has enough balance
    - Prevents race condition/double spend
    """
    try:
        data = request.get_json() or {}
        to_account = data.get("to_account")
        amount_raw = data.get("amount")
        description = data.get("description", "Transfer")

        if not to_account or amount_raw is None:
            return jsonify({"status": "error", "message": "Missing fields"}), 400

        try:
            amount = float(amount_raw)
            if amount <= 0:
                raise ValueError
        except Exception:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Lock sender row
                cur.execute(
                    """
                    SELECT account_number, balance
                    FROM users
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (current_user["user_id"],),
                )
                sender_row = cur.fetchone()
                if not sender_row:
                    return (
                        jsonify(
                            {"status": "error", "message": "Sender account not found"}
                        ),
                        404,
                    )

                sender_account, sender_balance = sender_row
                sender_balance = float(sender_balance)

                # Lock receiver row
                cur.execute(
                    """
                    SELECT id, account_number
                    FROM users
                    WHERE account_number = %s
                    FOR UPDATE
                    """,
                    (to_account,),
                )
                receiver_row = cur.fetchone()
                if not receiver_row:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Destination account not found",
                            }
                        ),
                        404,
                    )

                if sender_balance < amount:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Insufficient balance",
                            }
                        ),
                        400,
                    )

                # Perform updates atomically
                cur.execute(
                    """
                    UPDATE users
                    SET balance = balance - %s
                    WHERE id = %s
                    """,
                    (amount, current_user["user_id"]),
                )
                cur.execute(
                    """
                    UPDATE users
                    SET balance = balance + %s
                    WHERE account_number = %s
                    """,
                    (amount, to_account),
                )
                cur.execute(
                    """
                    INSERT INTO transactions
                    (from_account, to_account, amount, transaction_type, description)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (sender_account, to_account, amount, "transfer", description),
                )

            conn.commit()

            return jsonify(
                {
                    "status": "success",
                    "message": "Transfer completed",
                    "amount": amount,
                    "from_account": sender_account,
                    "to_account": to_account,
                }
            )

        except Exception as inner:
            conn.rollback()
            print(f"Transfer error: {inner}")
            return jsonify({"status": "error", "message": "Transfer failed"}), 500
        finally:
            return_connection(conn)

    except Exception as e:
        print(f"Transfer outer error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


# =========================================================
# TRANSACTION HISTORY
# =========================================================

@app.route("/transactions/<account_number>")
@token_required
def get_transaction_history(current_user, account_number):
    """
    Only allow user to view transactions for their own account.
    """
    try:
        # Verify ownership
        user_account = execute_query(
            """
            SELECT account_number
            FROM users
            WHERE id = %s AND account_number = %s
            """,
            (current_user["user_id"], account_number),
        )
        if not user_account:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Access denied for this account",
                    }
                ),
                403,
            )

        query = """
            SELECT 
                id,
                from_account,
                to_account,
                amount,
                timestamp,
                transaction_type,
                description
            FROM transactions
            WHERE from_account=%s OR to_account=%s
            ORDER BY timestamp DESC
        """
        transactions = execute_query(query, (account_number, account_number))

        transaction_list = [
            {
                "id": t[0],
                "from_account": t[1],
                "to_account": t[2],
                "amount": float(t[3]),
                "timestamp": str(t[4]),
                "type": t[5],
                "description": t[6],
            }
            for t in transactions
        ]

        return jsonify(
            {
                "status": "success",
                "account_number": account_number,
                "transactions": transaction_list,
            }
        )
    except Exception as e:
        print(f"Transaction history error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/transactions", methods=["GET"])
@token_required
def api_transactions(current_user):
    account_number = request.args.get("account_number")
    if not account_number:
        return jsonify({"error": "Account number required"}), 400

    # Reuse same logic
    return get_transaction_history(current_user, account_number)


# =========================================================
# PROFILE PICTURE UPLOAD (SECURE)
# =========================================================

@app.route("/upload_profile_picture", methods=["POST"])
@token_required
def upload_profile_picture(current_user):
    if "profile_picture" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["profile_picture"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    try:
        filename = secure_filename(file.filename)
        # Use UUID to avoid collisions
        filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        file.save(file_path)

        execute_query(
            "UPDATE users SET profile_picture = %s WHERE id = %s",
            (filename, current_user["user_id"]),
            fetch=False,
        )

        return jsonify(
            {
                "status": "success",
                "message": "Profile picture uploaded successfully",
                "path": f"/static/uploads/{filename}",
            }
        )

    except Exception as e:
        print(f"Profile picture upload error: {e}")
        return jsonify({"status": "error", "message": "Upload failed"}), 500


@app.route("/upload_profile_picture_url", methods=["POST"])
@token_required
def upload_profile_picture_url(current_user):
    """
    Safe version: only allow server-defined URLs.
    """
    try:
        data = request.get_json() or {}
        image_id = data.get("image_id")

        ALLOWED_IMAGES = {
            "unsplash_1": "https://images.unsplash.com/photo-1519125323398-675f0ddb6308",
            "imgur_cat": "https://i.imgur.com/Cat123.jpg",
            "imgur_dog": "https://i.imgur.com/Dog456.png",
        }

        if not image_id or image_id not in ALLOWED_IMAGES:
            return jsonify({"status": "error", "message": "Invalid image_id"}), 400

        image_url = ALLOWED_IMAGES[image_id]

        resp = requests.get(image_url, timeout=10, allow_redirects=True)
        if resp.status_code >= 400:
            return jsonify(
                {
                    "status": "error",
                    "message": f"Failed to fetch image (HTTP {resp.status_code})",
                }
            ), 400

        parsed_url = urlparse(image_url)
        basename = os.path.basename(parsed_url.path) or "downloaded"
        filename = secure_filename(basename)
        filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        with open(file_path, "wb") as f:
            f.write(resp.content)

        execute_query(
            "UPDATE users SET profile_picture = %s WHERE id = %s",
            (filename, current_user["user_id"]),
            fetch=False,
        )

        return jsonify(
            {
                "status": "success",
                "message": "Profile picture updated from predefined image",
                "path": f"/static/uploads/{filename}",
            }
        )

    except Exception as e:
        print(f"URL image import error: {e}")
        return jsonify({"status": "error", "message": "Import failed"}), 500


# =========================================================
# LOANS & ADMIN
# =========================================================

@app.route("/request_loan", methods=["POST"])
@token_required
def request_loan(current_user):
    try:
        data = request.get_json() or {}
        amount_raw = data.get("amount")
        try:
            amount = float(amount_raw)
            if amount <= 0:
                raise ValueError
        except Exception:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        execute_query(
            "INSERT INTO loans (user_id, amount) VALUES (%s, %s)",
            (current_user["user_id"], amount),
            fetch=False,
        )

        return jsonify(
            {"status": "success", "message": "Loan requested successfully"}
        )
    except Exception as e:
        print(f"Loan request error: {e}")
        return jsonify({"status": "error", "message": "Request failed"}), 500


@app.route("/sup3r_s3cr3t_admin")
@token_required
def admin_panel(current_user):
    if not current_user.get("is_admin"):
        return "Access Denied", 403

    users = execute_query(
        "SELECT id, username, account_number, balance, is_admin FROM users"
    )
    pending_loans = execute_query(
        "SELECT id, user_id, amount, status FROM loans WHERE status='pending'"
    )

    return render_template("admin.html", users=users, pending_loans=pending_loans)


@app.route("/admin/approve_loan/<int:loan_id>", methods=["POST"])
@token_required
def approve_loan(current_user, loan_id):
    if not current_user.get("is_admin"):
        return jsonify({"error": "Access Denied"}), 403

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Only approve pending loans
                cur.execute(
                    """
                    UPDATE loans
                    SET status='approved'
                    WHERE id = %s AND status='pending'
                    RETURNING user_id, amount
                    """,
                    (loan_id,),
                )
                loan_row = cur.fetchone()
                if not loan_row:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Loan not found or already approved",
                            }
                        ),
                        400,
                    )

                loan_user_id, loan_amount = loan_row

                cur.execute(
                    """
                    UPDATE users
                    SET balance = balance + %s
                    WHERE id = %s
                    """,
                    (loan_amount, loan_user_id),
                )

            conn.commit()

            return jsonify(
                {
                    "status": "success",
                    "message": "Loan approved",
                    "loan_id": loan_id,
                }
            )
        except Exception as inner:
            conn.rollback()
            print(f"Loan approval error: {inner}")
            return jsonify({"status": "error", "message": "Approval failed"}), 500
        finally:
            return_connection(conn)
    except Exception as e:
        print(f"Loan approval outer error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/admin/delete_account/<int:user_id>", methods=["POST"])
@token_required
def delete_account(current_user, user_id):
    if not current_user.get("is_admin"):
        return jsonify({"error": "Access Denied"}), 403

    try:
        execute_query(
            "DELETE FROM users WHERE id = %s",
            (user_id,),
            fetch=False,
        )

        return jsonify(
            {"status": "success", "message": "Account deleted successfully"}
        )
    except Exception as e:
        print(f"Delete account error: {e}")
        return jsonify({"status": "error", "message": "Delete failed"}), 500


@app.route("/admin/create_admin", methods=["POST"])
@token_required
def create_admin(current_user):
    if not current_user.get("is_admin"):
        return jsonify({"error": "Access Denied"}), 403

    try:
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify(
                {"status": "error", "message": "Username and password required"}
            ), 400

        account_number = generate_account_number()

        query = """
            INSERT INTO users (username, password, account_number, is_admin)
            VALUES (%s, %s, %s, TRUE)
        """
        params = (username, password, account_number)

        execute_query(query, params, fetch=False)

        return jsonify(
            {"status": "success", "message": "Admin created successfully"}
        )

    except Exception as e:
        print(f"Create admin error: {e}")
        return jsonify({"status": "error", "message": "Create admin failed"}), 500


# =========================================================
# PASSWORD RESET (SAFE MESSAGE, NO PIN LEAK)
# =========================================================

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = request.get_json() or {}
        username = data.get("username")

        if not username:
            return jsonify({"status": "error", "message": "Username required"}), 400

        user = execute_query(
            "SELECT id FROM users WHERE username=%s",
            (username,),
        )

        # Always return generic status to avoid enumeration
        if not user:
            return jsonify(
                {
                    "status": "success",
                    "message": "If this user exists, a reset PIN has been generated.",
                }
            )

        reset_pin = "".join(secrets.choice(string.digits) for _ in range(6))

        execute_query(
            "UPDATE users SET reset_pin = %s WHERE username = %s",
            (reset_pin, username),
            fetch=False,
        )

        # In real life, send via email/SMS. Here we just return generic msg.
        return jsonify(
            {
                "status": "success",
                "message": "If this user exists, a reset PIN has been generated.",
            }
        )
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({"status": "error", "message": "Request failed"}), 500


@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        data = request.get_json() or {}
        username = data.get("username")
        reset_pin = data.get("reset_pin")
        new_password = data.get("new_password")

        if not (username and reset_pin and new_password):
            return jsonify({"status": "error", "message": "Missing fields"}), 400

        user = execute_query(
            "SELECT id FROM users WHERE username = %s AND reset_pin = %s",
            (username, reset_pin),
        )

        if not user:
            # Generic invalid message
            return (
                jsonify(
                    {"status": "error", "message": "Invalid username or reset PIN"}
                ),
                400,
            )

        execute_query(
            "UPDATE users SET password = %s, reset_pin = NULL WHERE username = %s",
            (new_password, username),
            fetch=False,
        )

        return jsonify(
            {"status": "success", "message": "Password has been reset successfully"}
        )
    except Exception as e:
        print(f"Reset password error: {e}")
        return jsonify({"status": "error", "message": "Reset failed"}), 500


# =========================================================
# BILLING (CATEGORIES, BILLERS, PAYMENTS)
# =========================================================

@app.route("/api/bill-categories", methods=["GET"])
@token_required
def get_bill_categories(current_user):
    try:
        categories = execute_query(
            "SELECT id, name, description FROM bill_categories WHERE is_active = TRUE"
        )

        return jsonify(
            {
                "status": "success",
                "categories": [
                    {"id": c[0], "name": c[1], "description": c[2]} for c in categories
                ],
            }
        )
    except Exception as e:
        print(f"Bill categories error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/billers/by-category/<int:category_id>", methods=["GET"])
@token_required
def get_billers_by_category(current_user, category_id):
    try:
        query = """
            SELECT id, name, description, minimum_amount, maximum_amount
            FROM billers 
            WHERE category_id = %s AND is_active = TRUE
        """
        billers = execute_query(query, (category_id,))

        return jsonify(
            {
                "status": "success",
                "billers": [
                    {
                        "id": b[0],
                        "name": b[1],
                        "description": b[2],
                        "minimum_amount": float(b[3]),
                        "maximum_amount": float(b[4]) if b[4] else None,
                    }
                    for b in billers
                ],
            }
        )
    except Exception as e:
        print(f"Billers error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500


@app.route("/api/bill-payments/create", methods=["POST"])
@token_required
def create_bill_payment(current_user):
    """
    Safe bill payment:
    - Validates amount
    - Uses transaction for balance/card update + payment record
    """
    try:
        data = request.get_json() or {}

        biller_id = data.get("biller_id")
        payment_method = data.get("payment_method")
        card_id = data.get("card_id")
        amount_raw = data.get("amount")
        description = data.get("description", "Bill Payment")

        if not (biller_id and payment_method and amount_raw):
            return jsonify({"status": "error", "message": "Missing fields"}), 400

        try:
            amount = float(amount_raw)
            if amount <= 0:
                raise ValueError
        except Exception:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        reference = f"BILL-{int(time.time())}"

        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Check biller exists and is active
                cur.execute(
                    """
                    SELECT id, minimum_amount, maximum_amount
                    FROM billers
                    WHERE id = %s AND is_active = TRUE
                    """,
                    (biller_id,),
                )
                biller_row = cur.fetchone()
                if not biller_row:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Biller not found or inactive",
                            }
                        ),
                        404,
                    )

                _, min_amt, max_amt = biller_row
                min_amt = float(min_amt)
                if amount < min_amt:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": f"Amount must be >= {min_amt}",
                            }
                        ),
                        400,
                    )
                if max_amt is not None and amount > float(max_amt):
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": f"Amount must be <= {float(max_amt)}",
                            }
                        ),
                        400,
                    )

                # Insert payment skeleton
                cur.execute(
                    """
                    INSERT INTO bill_payments
                    (user_id, biller_id, amount, payment_method, card_id,
                     reference_number, description, status, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',NOW())
                    RETURNING id
                    """,
                    (
                        current_user["user_id"],
                        biller_id,
                        amount,
                        payment_method,
                        card_id if payment_method == "virtual_card" else None,
                        reference,
                        description,
                    ),
                )
                payment_row = cur.fetchone()
                payment_id = payment_row[0]

                if payment_method == "balance":
                    # Lock user balance row
                    cur.execute(
                        """
                        SELECT balance
                        FROM users
                        WHERE id = %s
                        FOR UPDATE
                        """,
                        (current_user["user_id"],),
                    )
                    user_row = cur.fetchone()
                    if not user_row:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "User account not found",
                                }
                            ),
                            404,
                        )
                    balance = float(user_row[0])
                    if balance < amount:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "Insufficient balance",
                                }
                            ),
                            400,
                        )

                    cur.execute(
                        """
                        UPDATE users
                        SET balance = balance - %s
                        WHERE id = %s
                        """,
                        (amount, current_user["user_id"]),
                    )

                elif payment_method == "virtual_card":
                    if not card_id:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "card_id required for virtual_card",
                                }
                            ),
                            400,
                        )

                    # Lock card row
                    cur.execute(
                        """
                        SELECT current_balance, is_frozen
                        FROM virtual_cards
                        WHERE id = %s AND user_id = %s
                        FOR UPDATE
                        """,
                        (card_id, current_user["user_id"]),
                    )
                    card_row = cur.fetchone()
                    if not card_row:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "Card not found or access denied",
                                }
                            ),
                            403,
                        )

                    card_balance, is_frozen = card_row
                    card_balance = float(card_balance)

                    if is_frozen:
                        return (
                            jsonify(
                                {"status": "error", "message": "Card is frozen"}
                            ),
                            400,
                        )

                    if card_balance < amount:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "message": "Insufficient card balance",
                                }
                            ),
                            400,
                        )

                    cur.execute(
                        """
                        UPDATE virtual_cards
                        SET current_balance = current_balance - %s
                        WHERE id = %s
                        """,
                        (amount, card_id),
                    )

                else:
                    return (
                        jsonify(
                            {"status": "error", "message": "Invalid payment method"}
                        ),
                        400,
                    )

                # Mark payment as completed
                cur.execute(
                    """
                    UPDATE bill_payments
                    SET status='completed', processed_at=NOW()
                    WHERE id = %s
                    """,
                    (payment_id,),
                )

            conn.commit()

            return jsonify(
                {
                    "status": "success",
                    "message": "Payment processed successfully",
                    "payment_details": {
                        "reference": reference,
                        "amount": amount,
                        "payment_method": payment_method,
                        "biller_id": biller_id,
                    },
                }
            )

        except Exception as inner:
            conn.rollback()
            print(f"Bill payment error: {inner}")
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Payment transaction failed",
                    }
                ),
                500,
            )
        finally:
            return_connection(conn)

    except Exception as e:
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


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    init_db()
    init_auth_routes(app)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

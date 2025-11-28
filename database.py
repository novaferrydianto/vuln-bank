import os
import time
import logging
from datetime import datetime

import psycopg2
from psycopg2 import pool
import bcrypt

# =====================================================
# LOGGING (NO SECRET LEAK)
# =====================================================
logger = logging.getLogger("vulnbank.db")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [DB] %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# =====================================================
# DATABASE CONFIG (ENV ONLY)
# =====================================================
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST", "db"),
    "port": os.getenv("DB_PORT", "5432"),
    # Uncomment if DB supports TLS
    # "sslmode": os.getenv("DB_SSLMODE", "require"),
}

def _safe_config(cfg: dict) -> dict:
    redacted = dict(cfg)
    if redacted.get("password"):
        redacted["password"] = "***redacted***"
    return redacted

logger.info("Loaded DB config: %s", _safe_config(DB_CONFIG))

# =====================================================
# PASSWORD SECURITY (bcrypt)
# =====================================================
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode(),
            password_hash.encode(),
        )
    except Exception:
        return False

# =====================================================
# CONNECTION POOL
# =====================================================
connection_pool: pool.SimpleConnectionPool | None = None

def init_connection_pool(
    min_connections=1,
    max_connections=10,
    max_retries=5,
    retry_delay=2,
):
    global connection_pool
    retry = 0

    while retry < max_retries:
        try:
            connection_pool = psycopg2.pool.SimpleConnectionPool(
                min_connections,
                max_connections,
                **DB_CONFIG,
            )
            logger.info("✅ Database connection pool ready")
            return
        except Exception as e:
            retry += 1
            logger.error("DB connection failed (%s/%s): %s", retry, max_retries, e)
            time.sleep(retry_delay)

    raise RuntimeError("❌ Database connection failed (max retries reached)")

def get_connection():
    if not connection_pool:
        raise RuntimeError("Connection pool not initialized")
    return connection_pool.getconn()

def return_connection(conn):
    if connection_pool and conn:
        connection_pool.putconn(conn)

# =====================================================
# DATABASE INITIALIZATION (SECURE SCHEMA)
# =====================================================
def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # USERS
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    account_number TEXT NOT NULL UNIQUE,
                    balance NUMERIC(15,2) NOT NULL DEFAULT 1000.00 CHECK (balance >= 0),
                    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                    profile_picture TEXT,
                    reset_pin_hash TEXT,
                    reset_pin_expires_at TIMESTAMP
                )
            """)

            # TRANSACTIONS (money-safe)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id SERIAL PRIMARY KEY,
                    from_account TEXT NOT NULL,
                    to_account TEXT NOT NULL,
                    amount NUMERIC(15,2) NOT NULL CHECK (amount > 0),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    transaction_type TEXT NOT NULL,
                    description TEXT,
                    CONSTRAINT no_self_transfer CHECK (from_account <> to_account)
                )
            """)

            # LOANS
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS loans (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    amount NUMERIC(15,2) CHECK (amount > 0),
                    status TEXT DEFAULT 'pending'
                )
            """)

            # BILL CATEGORIES
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bill_categories (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)

            # BILLERS
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS billers (
                    id SERIAL PRIMARY KEY,
                    category_id INTEGER REFERENCES bill_categories(id),
                    name TEXT NOT NULL,
                    account_number TEXT NOT NULL,
                    minimum_amount NUMERIC(15,2) DEFAULT 0 CHECK (minimum_amount >= 0),
                    maximum_amount NUMERIC(15,2),
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)

            # BILL PAYMENTS (reference UNIQUE)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bill_payments (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    biller_id INTEGER REFERENCES billers(id),
                    amount NUMERIC(15,2) NOT NULL CHECK (amount > 0),
                    payment_method TEXT NOT NULL,
                    reference_number TEXT UNIQUE NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # DEFAULT ADMIN
            cursor.execute("SELECT 1 FROM users WHERE username = %s", ("admin",))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO users (username, password_hash, account_number, balance, is_admin)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    "admin",
                    hash_password("admin123"),
                    "ADMIN001",
                    1_000_000,
                    True
                ))

            conn.commit()
            logger.info("✅ Database schema initialized (secure)")

    except Exception as e:
        conn.rollback()
        logger.exception("DB init failed: %s", e)
        raise
    finally:
        return_connection(conn)

# =====================================================
# QUERY HELPERS (SAFE)
# =====================================================
def execute_query(query, params=None, fetch=True):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            if fetch:
                return cursor.fetchall()

            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Query failed: %s", e)
        raise
    finally:
        return_connection(conn)

def execute_transaction(queries_and_params):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for query, params in queries_and_params:
                cursor.execute(query, params)
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Transaction rollback: %s", e)
        raise
    finally:
        return_connection(conn)

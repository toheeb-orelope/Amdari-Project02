"""
SecureFlow auth-service — INTENTIONALLY VULNERABLE.
Every vulnerability is tagged with its Vulnerability Index ID in a comment.
Do not deploy outside an isolated lab.
"""
import os
import hashlib
import jwt
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

# AV-07 — Hardcoded JWT Secret. Matches the value committed in docker-compose.yml and .env.
SECRET_KEY = os.getenv("JWT_SECRET", "redacted")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "auth-db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "authdb"),
    "user": os.getenv("DB_USER", "authuser"),
    "password": os.getenv("DB_PASSWORD", "redacted"),
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


# AV-05 — Insecure Password Storage. MD5 with no salt.
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/login", methods=["POST"])
def login():
    """
    AV-01 — SQL Injection on login.
    AV-04 — No rate limiting, lockout, or CAPTCHA.
    Payload: {"username": "admin'--", "password": "anything"} bypasses auth.
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()

    # Deliberately vulnerable string concatenation.
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password_hash = '{hash_password(password)}'"
    )
    try:
        cur.execute(query)
        row = cur.fetchone()
    except Exception as exc:
        # AV-08 — Sensitive data in error responses (full exception to client).
        return jsonify({"error": str(exc), "query": query}), 500
    finally:
        cur.close()
        conn.close()

    if not row:
        return jsonify({"error": "invalid credentials"}), 401

    user_id, uname, role = row
    # TV-07-adjacent — JWT with no expiry claim.
    token = jwt.encode(
        {"user_id": user_id, "username": uname, "role": role},
        SECRET_KEY,
        algorithm="HS256",
    )
    return jsonify({"token": token, "user_id": user_id, "role": role}), 200


@app.route("/register", methods=["POST"])
def register():
    """
    AV-02 — SQL Injection on registration (string-interpolated INSERT).
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")

    conn = get_db()
    cur = conn.cursor()

    query = (
        "INSERT INTO users (username, password_hash, email, role) "
        f"VALUES ('{username}', '{hash_password(password)}', '{email}', 'user') "
        "RETURNING id"
    )
    try:
        cur.execute(query)
        new_id = cur.fetchone()[0]
        conn.commit()
    except Exception as exc:
        # AV-08 — Stack trace / query leakage.
        return jsonify({"error": str(exc), "query": query}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify({"id": new_id, "username": username}), 201


@app.route("/admin", methods=["GET", "POST"])
def admin():
    """
    AV-06 — Admin panel with no server-side role check.
    Any authenticated user (or anyone with a forgeable JWT — see AV-03)
    can call this endpoint.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing token"}), 401
    token = auth_header.split(" ", 1)[1]

    try:
        # AV-03 — Hardcoded secret means an attacker can forge tokens.
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 401

    # Deliberately missing: `if payload.get("role") != "admin": return 403`
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role FROM users")
    users = [
        {"id": r[0], "username": r[1], "email": r[2], "role": r[3]}
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify({"users": users, "actor": payload.get("username")}), 200


@app.route("/verify", methods=["POST"])
def verify():
    """Used by transaction-service to validate tokens. Intentionally accepts expired tokens."""
    data = request.get_json() or {}
    token = data.get("token", "")
    try:
        # TV-07 — No expiry / revocation check.
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False}
        )
        return jsonify({"valid": True, "payload": payload}), 200
    except Exception as exc:
        return jsonify({"valid": False, "error": str(exc)}), 401


if __name__ == "__main__":
    # IV-related — Flask dev server, debug mode exposes the interactive debugger.
    app.run(host="0.0.0.0", port=5001, debug=True)

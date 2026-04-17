"""
SecureFlow transaction-service — INTENTIONALLY VULNERABLE.
Every vulnerability is tagged with its Vulnerability Index ID in a comment.
"""
import os
import requests
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:5001")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "transaction-db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "transactiondb"),
    "user": os.getenv("DB_USER", "txuser"),
    "password": os.getenv("DB_PASSWORD", "redacted"),
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


def get_user_from_token():
    """
    Returns the authenticated user payload, or None.
    Deliberately does NOT enforce token expiry (TV-07 via auth-service /verify).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    try:
        r = requests.post(
            f"{AUTH_SERVICE_URL}/verify", json={"token": token}, timeout=5
        )
        if r.status_code == 200 and r.json().get("valid"):
            return r.json().get("payload")
    except Exception:
        return None
    return None


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/balance/<account_id>", methods=["GET"])
def balance(account_id):
    """
    TV-01 — IDOR. Returns balance for any account_id.
    No check that request user owns the account.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, owner_id, balance FROM accounts WHERE id = %s", (account_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"error": "account not found"}), 404
    # Deliberately missing: `if row[1] != user["user_id"]: return 403`
    return jsonify({"account_id": row[0], "owner_id": row[1], "balance": float(row[2])}), 200


@app.route("/transactions/<account_id>", methods=["GET"])
def transactions(account_id):
    """
    TV-02 — IDOR. Returns full transaction history for any account.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, from_account, to_account, amount, notes, created_at "
        "FROM transactions WHERE from_account = %s OR to_account = %s "
        "ORDER BY created_at DESC",
        (account_id, account_id),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return (
        jsonify(
            {
                "account_id": account_id,
                "transactions": [
                    {
                        "id": r[0],
                        "from": r[1],
                        "to": r[2],
                        "amount": float(r[3]),
                        "notes": r[4],  # FV-02 source — stored XSS rendered by frontend.
                        "created_at": r[5].isoformat() if r[5] else None,
                    }
                    for r in rows
                ],
            }
        ),
        200,
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    """
    TV-03 — No validation that amount > 0 (negative transfer drains recipient).
    TV-05 — No check on maximum or account balance (negative balances possible).
    TV-06 — No CSRF token validation.
    TV-07 — Accepts expired tokens via auth-service /verify behaviour.
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401

    data = request.get_json() or {}
    from_account = data.get("from_account")
    to_account = data.get("to_account")
    amount = data.get("amount")
    notes = data.get("notes", "")  # FV-02 — notes stored verbatim, later rendered unsafely.

    # Deliberately missing: amount > 0 check, balance check, CSRF check, ownership check.

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE accounts SET balance = balance - %s WHERE id = %s",
            (amount, from_account),
        )
        cur.execute(
            "UPDATE accounts SET balance = balance + %s WHERE id = %s",
            (amount, to_account),
        )
        cur.execute(
            "INSERT INTO transactions (from_account, to_account, amount, notes) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (from_account, to_account, amount, notes),
        )
        tx_id = cur.fetchone()[0]
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify({"transaction_id": tx_id, "status": "completed"}), 200


@app.route("/cards", methods=["POST"])
def create_card():
    """
    TV-04 — Mass assignment. Accepts arbitrary JSON including fields
    that should be system-controlled (internal_limit, is_corporate).
    """
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401

    data = request.get_json() or {}

    conn = get_db()
    cur = conn.cursor()
    # Deliberately splats the entire payload into the INSERT.
    columns = list(data.keys())
    values = list(data.values())
    placeholders = ", ".join(["%s"] * len(columns))
    query = f"INSERT INTO cards ({', '.join(columns)}) VALUES ({placeholders}) RETURNING id"
    try:
        cur.execute(query, values)
        card_id = cur.fetchone()[0]
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify({"card_id": card_id}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)

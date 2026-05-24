"""
SecureFlow frontend — INTENTIONALLY VULNERABLE.
Server-rendered Flask UI that calls auth-service and transaction-service.
"""
import os
import requests
from flask import Flask, request, session, redirect, url_for, render_template_string

# FV-03 — Jinja2 autoescape disabled, enabling XSS.
app = Flask(__name__)
app.jinja_env.autoescape = False

# FV-03 — Session hijacking. Weak committed secret.
app.secret_key = os.getenv("SESSION_SECRET", "redacted")

AUTH_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:5001")
TX_URL = os.getenv("TRANSACTION_SERVICE_URL", "http://transaction-service:5002")


LOGIN_TEMPLATE = """
<!doctype html>
<html><head><title>SecureFlow — Login</title></head>
<body>
  <h1>SecureFlow Banking</h1>
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
  <form method="POST" action="/login">
    <!-- FV-05 — no CSRF token. -->
    <label>Username: <input name="username"></label><br>
    <label>Password: <input name="password" type="password"></label><br>
    <button type="submit">Log in</button>
  </form>
  <p><a href="/register">Register</a></p>
</body></html>
"""




@app.after_request
def add_headers(resp):
    # FV-06 — no X-Frame-Options or CSP frame-ancestors.
    # FV-07 — no CSP, X-Content-Type-Options, HSTS, Referrer-Policy.
    return resp


@app.route("/")
def index():
    if "token" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            r = requests.post(
                f"{AUTH_URL}/login",
                json={
                    "username": request.form.get("username"),
                    "password": request.form.get("password"),
                },
                timeout=5,
            )
            if r.status_code == 200:
                body = r.json()
                session["token"] = body["token"]
                session["username"] = request.form.get("username")
                session["user_id"] = body["user_id"]
                return redirect(url_for("dashboard"))
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
        except Exception as exc:
            return render_template_string(LOGIN_TEMPLATE, error=str(exc))
    return render_template_string(LOGIN_TEMPLATE, error=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        requests.post(
            f"{AUTH_URL}/register",
            json={
                "username": request.form.get("username"),
                "password": request.form.get("password"),
                "email": request.form.get("email"),
            },
            timeout=5,
        )
        return redirect(url_for("login"))
    return """
    <form method="POST">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <input name="email" placeholder="email">
      <button>Register</button>
    </form>
    """


@app.route("/dashboard")
def dashboard():
    if "token" not in session:
        return redirect(url_for("login"))

    # FV-01 — reflected XSS via query param.
    message = request.args.get("msg", "")

    try:
        r = requests.get(
            f"{TX_URL}/transactions/{session['user_id']}",
            headers={"Authorization": f"Bearer {session['token']}"},
            timeout=5,
        )
        transactions = r.json().get("transactions", []) if r.status_code == 200 else []
    except Exception:
        transactions = []

    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session.get("username", ""),
        message=message,
        transactions=transactions,
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    if "token" not in session:
        return redirect(url_for("login"))
    requests.post(
        f"{TX_URL}/transfer",
        headers={"Authorization": f"Bearer {session['token']}"},
        json={
            "from_account": request.form.get("from_account"),
            "to_account": request.form.get("to_account"),
            "amount": float(request.form.get("amount", "0")),
            "notes": request.form.get("notes", ""),
        },
        timeout=5,
    )
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
attempt_log = deque()
attempt_window = timedelta(seconds=30)
LOCKOUT_THRESHOLD = 25
payload_file = Path(__file__).with_name("payloads.txt")

with payload_file.open() as handle:
    KNOWN_PAYLOADS = [line.strip() for line in handle if line.strip()]

PASSWORD_INVALID_USERS = {"patel", "mendoza", "hill"}
SPECIAL_MESSAGES = {
    "doe": "Welcome to intranet. News: We backup all of your C:\\ drive starting 2026-01-01.",
    "tay": "Error: Employee contract not found (probably expired).",
}


def prune_attempts():
    now = datetime.utcnow()
    while attempt_log and attempt_log[0] < now - attempt_window:
        attempt_log.popleft()
    return now


def log_attempt(now):
    attempt_log.append(now)
    return len(attempt_log) >= LOCKOUT_THRESHOLD


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "payload_count": len(KNOWN_PAYLOADS)})


@app.route("/", methods=["GET"])
def index():
    return """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8"/>
            <title>Intruder Demo Login</title>
            <style>
                body { font-family: sans-serif; margin: 2rem; }
                fieldset { max-width: 320px; }
            </style>
        </head>
        <body>
            <h1>Intruder Demo Login</h1>
            <p>This form illustrates the JSON POST accepted at <code>/login</code>.</p>
            <form id="login-form">
                <fieldset>
                    <legend>Credentials</legend>
                    <label>Username
                        <input type="text" name="username" required/>
                    </label><br/><br/>
                    <label>Password
                        <input type="password" name="password" required/>
                    </label><br/><br/>
                    <button type="submit">Submit</button>
                </fieldset>
            </form>
            <pre id="response" style="background:#f4f4f4;padding:1rem;margin-top:1rem;"></pre>
            <script>
                const form = document.getElementById("login-form");
                const response = document.getElementById("response");
                form.addEventListener("submit", async (event) => {
                    event.preventDefault();
                    const formData = new FormData(form);
                    const payload = {
                        username: formData.get("username"),
                        password: formData.get("password"),
                    };
                    const login = await fetch("/login", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify(payload),
                    });
                    const body = await login.json();
                    const text = `Status: ${login.status}\\n${JSON.stringify(body, null, 2)}`;
                    response.textContent = text;
                });
            </script>
        </body>
        </html>
    """


@app.route("/login", methods=["POST"])
def login():
    now = prune_attempts()
    username = (request.json or {}).get("username", "")
    password = (request.json or {}).get("password", "")

    locked_out = log_attempt(now)
    if locked_out:
        return jsonify(
            {"success": False,
             "message": "Access denied: too many failed attempts."}), 429

    lower_username = username.lower()
    if username not in KNOWN_PAYLOADS:
        return jsonify({"success": False, "message": "Login failed."}), 401

    if lower_username in PASSWORD_INVALID_USERS:
        return jsonify({"success": False, "message": "Password invalid."}), 401

    if "'" in username:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"SQL syntax error near '{username}'; SQLSTATE[42000]",
                }
            ),
            400,
        )

    if password == username:
        special = SPECIAL_MESSAGES.get(lower_username)
        if special:
            return jsonify({"success": False, "message": special}), 403

    return jsonify({"success": False, "message": "Login failed."}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)

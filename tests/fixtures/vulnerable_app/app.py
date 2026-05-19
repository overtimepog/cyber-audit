"""
Vulnerable Flask application for testing cyber-audit pipeline.

Contains deliberate vulnerabilities:
- SQL injection (line ~45)
- Command injection (line ~70)
- Path traversal (line ~95)
- Reflected XSS (line ~120)

DO NOT DEPLOY. For security audit testing only.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'supersecret')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password123')")
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# VULNERABILITY 1: SQL Injection
# ---------------------------------------------------------------------------
# The /login endpoint concatenates user input directly into SQL query.
# Attack: username=admin'--  bypasses authentication.

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        # VULNERABLE: string interpolation in SQL
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            return f"Welcome {user['username']}!"
        return "Login failed"
    return '''
        <form method="post">
            <input name="username" placeholder="username">
            <input name="password" type="password" placeholder="password">
            <button type="submit">Login</button>
        </form>
    '''

# ---------------------------------------------------------------------------
# VULNERABILITY 2: Command Injection
# ---------------------------------------------------------------------------
# The /ping endpoint passes user input to subprocess without sanitization.
# Attack: /ping?host=8.8.8.8;cat /etc/passwd

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: shell=True with unsanitized user input
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"

# ---------------------------------------------------------------------------
# VULNERABILITY 3: Path Traversal
# ---------------------------------------------------------------------------
# The /read endpoint allows reading arbitrary files via path traversal.
# Attack: /read?file=../../../etc/passwd

@app.route("/read")
def read_file():
    filename = request.args.get("file", "README.md")
    base_dir = os.path.join(os.path.dirname(__file__), "files")
    # VULNERABLE: no path sanitization
    filepath = os.path.join(base_dir, filename)
    try:
        with open(filepath) as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "File not found", 404

# ---------------------------------------------------------------------------
# VULNERABILITY 4: Reflected XSS
# ---------------------------------------------------------------------------
# The /search endpoint reflects user input directly into HTML.
# Attack: /search?q=<script>alert(1)</script>

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: unescaped user input in HTML
    template = f"<h1>Search results for: {query}</h1><p>No results found.</p>"
    return render_template_string(template)

# ---------------------------------------------------------------------------
# Non-vulnerable routes (for comparison)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return "Vulnerable Test App — for security audit testing only"

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5000)

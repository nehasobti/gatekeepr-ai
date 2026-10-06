"""Vulnerable sample application with planted security and quality issues."""

import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Planted Issue 1: Hardcoded sensitive API credential
api_key = "ghp_1234567890abcdef1234567890abcdef"


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Planted Issue 2: SQL Injection via string formatting
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return str(cursor.fetchall())


# Planted Issue 3: Missing authentication on administrative endpoint
@app.route("/admin/dashboard")
def admin_dashboard():
    # Planted Issue 4: Cross-site scripting (XSS) via unescaped template string
    name = request.args.get("name", "Admin")
    return render_template_string("<h1>Welcome, " + name + "</h1>")


@app.route("/session/load", methods=["POST"])
def load_session():
    # Planted Issue 5: Insecure deserialization
    raw_payload = request.get_data()
    session_data = pickle.loads(raw_payload)
    return str(session_data)

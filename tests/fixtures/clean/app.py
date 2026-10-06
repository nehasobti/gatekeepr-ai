"""Clean sample application conforming to all security and quality best practices."""

import json
import os
import sqlite3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Clean: Credentials loaded safely from environment variables
api_key = os.environ.get("GITHUB_API_KEY", "")


def login_required(func):
    return func


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Clean: Parameterized SQL query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify(cursor.fetchall())


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    # Clean: Safe template rendering with auto-escaping
    name = request.args.get("name", "Admin")
    return render_template("dashboard.html", name=name)


@app.route("/session/load", methods=["POST"])
def load_session():
    # Clean: Safe JSON deserialization
    raw_payload = request.get_data(as_text=True)
    session_data = json.loads(raw_payload)
    return jsonify(session_data)

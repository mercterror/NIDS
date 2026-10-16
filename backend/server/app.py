import os
import sys
import sqlite3
import re

from datetime import datetime, timedelta

# Add the backend project root to Python's import path.
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    get_jwt_identity,
)

from database.database import IDSDatabase
from server.auth import auth_bp


# ============================================================
# FLASK AND JWT CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is not set"
    )

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)

db = IDSDatabase()
jwt = JWTManager(app)

CORS(app)

app.register_blueprint(auth_bp)


# ============================================================
# JWT TOKEN REVOCATION
# ============================================================

@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    conn = db.connect()

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ?",
            (jwt_payload["jti"],),
        )
        return cursor.fetchone() is not None

    finally:
        conn.close()


# ============================================================
# CURRENT USER AND ADMINISTRATOR ACCESS
# ============================================================

def get_current_user():
    user_id = get_jwt_identity()

    conn = db.connect()
    conn.row_factory = sqlite3.Row

    try:
        user = conn.execute(
            """
            SELECT id, username, email, role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        return dict(user) if user else None

    finally:
        conn.close()


def require_admin():
    user = get_current_user()

    if user is None:
        return None, (
            jsonify({"error": "User not found"}),
            404,
        )

    if user["role"] != "admin":
        return None, (
            jsonify({
                "error": "Administrator access required"
            }),
            403,
        )

    return user, None


# ============================================================
# BASIC API STATUS
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "NIDS API is running",
        "status": "online",
    }), 200


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.route("/api/dashboard/stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    stats = db.get_dashboard_stats()
    return jsonify(stats), 200


# ============================================================
# RECENT ATTACKS
# ============================================================

@app.route("/api/attacks", methods=["GET"])
@jwt_required()
def recent_attacks():
    attacks = db.get_recent_attacks(limit=50)
    return jsonify(attacks), 200


# ============================================================
# RECENT TRAFFIC
# ============================================================

@app.route("/api/traffic", methods=["GET"])
@jwt_required()
def recent_traffic():
    traffic = db.get_recent_traffic(limit=100)
    return jsonify(traffic), 200


# ============================================================
# PROTOCOL STATISTICS
# ============================================================

@app.route("/api/protocols", methods=["GET"])
@jwt_required()
def protocol_statistics():
    protocols = db.get_protocol_statistics()
    return jsonify(protocols), 200


# ============================================================
# CONNECTED DEVICES
# ============================================================

@app.route("/api/devices", methods=["GET"])
@jwt_required()
def recent_devices():
    devices = db.get_recent_devices()
    return jsonify(devices), 200


# ============================================================
# BLOCKED ENTITIES
# ============================================================

@app.route("/api/blocked", methods=["GET"])
@jwt_required()
def blocked_entities():
    blocked_ips = db.get_blocked_ips()
    return jsonify(blocked_ips), 200


# ============================================================
# GET ADMINISTRATOR NOTIFICATION SETTINGS
# ============================================================

@app.route("/api/settings/notifications", methods=["GET"])
@jwt_required()
def get_notification_settings():
    user, error = require_admin()

    if error:
        return error

    conn = db.connect()

    try:
        row = conn.execute(
            """
            SELECT alert_email, telegram_chat_id
            FROM notification_settings
            WHERE id = 1
            """
        ).fetchone()

        return jsonify({
            # Login email and alert recipient are separate settings.
            "account_email": user["email"],
            "alert_email": row[0] if row else "",
            "telegram_chat_id": row[1] if row else "",
            "role": user["role"],
        }), 200

    finally:
        conn.close()


# ============================================================
# UPDATE ADMINISTRATOR NOTIFICATION SETTINGS
# ============================================================

@app.route("/api/settings/notifications", methods=["PUT"])
@jwt_required()
def update_notification_settings():
    user, error = require_admin()

    if error:
        return error

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A valid JSON object is required"
        }), 400

    conn = db.connect()

    try:
        # Preserve existing settings when a client updates only one field.
        current = conn.execute(
            """
            SELECT alert_email, telegram_chat_id
            FROM notification_settings
            WHERE id = 1
            """
        ).fetchone()

        current_email = current[0] if current else ""
        current_chat_id = current[1] if current else ""

        alert_email = data.get(
            "alert_email",
            current_email or "",
        )

        chat_id = data.get(
            "telegram_chat_id",
            current_chat_id or "",
        )

        if not isinstance(alert_email, str):
            return jsonify({
                "error": "Alert email must be text"
            }), 400

        if not isinstance(chat_id, str):
            return jsonify({
                "error": "Telegram Chat ID must be text"
            }), 400

        alert_email = alert_email.strip()
        chat_id = chat_id.strip()

        # Validate the administrator-selected alert email.
        if alert_email and not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            alert_email,
        ):
            return jsonify({
                "error": "Enter a valid alert email address"
            }), 400

        if len(alert_email) > 254:
            return jsonify({
                "error": "Alert email is too long"
            }), 400

        # Telegram chat IDs are numeric and may be negative.
        if len(chat_id) > 64:
            return jsonify({
                "error": "Telegram Chat ID is too long"
            }), 400

        if chat_id:
            numeric_part = (
                chat_id[1:]
                if chat_id.startswith("-")
                else chat_id
            )

            if not numeric_part.isdigit():
                return jsonify({
                    "error": "Enter a valid numeric Telegram Chat ID"
                }), 400

        conn.execute(
            """
            INSERT INTO notification_settings (
                id,
                alert_email,
                telegram_chat_id,
                updated_at
            )
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                alert_email = excluded.alert_email,
                telegram_chat_id = excluded.telegram_chat_id,
                updated_at = excluded.updated_at
            """,
            (
                alert_email,
                chat_id,
                datetime.now().isoformat(),
            ),
        )

        conn.commit()

        return jsonify({
            "message": "Notification settings saved",
            "alert_email": alert_email,
            "telegram_chat_id": chat_id,
        }), 200

    finally:
        conn.close()


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
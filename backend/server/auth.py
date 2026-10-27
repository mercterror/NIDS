
from datetime import datetime, timedelta
import sqlite3

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from werkzeug.security import generate_password_hash, check_password_hash

from database.database import IDSDatabase


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
db = IDSDatabase()


def require_admin():
    """Verify the authenticated user's current database role."""
    user_id = get_jwt_identity()
    conn = db.connect()

    try:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT id, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if not user:
            return False, (
                jsonify({"error": "User not found"}),
                404,
            )

        if user["role"] != "admin":
            return False, (
                jsonify({"error": "Administrator access required"}),
                403,
            )

        return True, None

    finally:
        conn.close()


@auth_bp.route("/register", methods=["POST"])
@jwt_required()
def register():
    """Allow an authenticated administrator to create another admin."""
    allowed, error = require_admin()

    if not allowed:
        return error

    data = request.get_json(silent=True) or {}

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not all(isinstance(value, str) for value in (username, email, password)):
        return jsonify({"error": "All fields must be text"}), 400

    username = username.strip()
    email = email.strip().lower()

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if len(username) > 80:
        return jsonify({"error": "Username must be 80 characters or fewer"}), 400

    if len(email) > 254 or "@" not in email:
        return jsonify({"error": "Enter a valid email address"}), 400

    if len(password) < 12:
        return jsonify({
            "error": "Password must be at least 12 characters long"
        }), 400

    if len(password) > 128:
        return jsonify({"error": "Password is too long"}), 400

    conn = db.connect()

    try:
        conn.execute(
            """
            INSERT INTO users (
                username, email, password_hash, role, created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                email,
                generate_password_hash(password),
                "admin",
                datetime.now().isoformat(),
            ),
        )
        conn.commit()

        return jsonify({
            "message": "Administrator account created successfully"
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Username or email already exists"
        }), 409

    except sqlite3.Error:
        return jsonify({"error": "Unable to create account"}), 500

    finally:
        conn.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    identifier = data.get("identifier", "")
    password = data.get("password", "")

    if not isinstance(identifier, str) or not isinstance(password, str):
        return jsonify({
            "error": "Username/email and password are required"
        }), 400

    identifier = identifier.strip()

    if not identifier or not password:
        return jsonify({
            "error": "Username/email and password are required"
        }), 400

    conn = db.connect()

    try:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            """
            SELECT id, username, email, password_hash, role
            FROM users
            WHERE username = ? OR email = ?
            """,
            (identifier, identifier.lower()),
        ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(
            identity=str(user["id"]),
            additional_claims={"role": user["role"]},
            expires_delta=timedelta(minutes=15),
        )

        return jsonify({
            "access_token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            },
        }), 200

    finally:
        conn.close()


@auth_bp.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    conn = db.connect()

    try:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            """
            SELECT id, username, email, role, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify(dict(user)), 200

    finally:
        conn.close()


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    token = get_jwt()
    conn = db.connect()

    try:
        conn.execute(
            "INSERT INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)",
            (token["jti"], datetime.now().isoformat()),
        )
        conn.commit()

    finally:
        conn.close()

    return jsonify({"message": "Logged out successfully"}), 200

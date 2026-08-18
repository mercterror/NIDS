import sqlite3

from flask import Blueprint, jsonify

from backend.database.database import IDSDatabase

api = Blueprint("api", __name__)

db = IDSDatabase()


# ==========================================
# DASHBOARD
# ==========================================

@api.route("/dashboard", methods=["GET"])
def dashboard():

    return jsonify(
        db.get_dashboard_stats()
    )


# ==========================================
# TRAFFIC LOGS
# ==========================================

@api.route("/traffic", methods=["GET"])
def traffic():

    return jsonify(
        db.get_recent_traffic()
    )


# ==========================================
# ATTACK LOGS
# ==========================================

@api.route("/attacks", methods=["GET"])
def attacks():

    return jsonify(
        db.get_recent_attacks()
    )


# ==========================================
# DEVICES
# ==========================================

@api.route("/devices", methods=["GET"])
def devices():

    return jsonify(
        db.get_recent_devices()
    )


# ==========================================
# PROTOCOL STATISTICS
# ==========================================

@api.route("/statistics", methods=["GET"])
def statistics():

    return jsonify(
        db.get_protocol_statistics()
    )

# to dashboard to get the live traffic
@api.route("/traffic-history", methods=["GET"])
def traffic_history():

    conn = db.connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            packet_rate
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()

    rows.reverse()

    return jsonify(rows)
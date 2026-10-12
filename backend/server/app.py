import os
import sys

# Add the backend project root to Python's import path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify
from flask_cors import CORS
from database.database import IDSDatabase

app = Flask(__name__)
CORS(app)

db = IDSDatabase()


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "NIDS API is running",
        "status": "online"
    })


@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    stats = db.get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/attacks", methods=["GET"])
def recent_attacks():
    attacks = db.get_recent_attacks(limit=50)
    return jsonify(attacks)


@app.route("/api/traffic", methods=["GET"])
def recent_traffic():
    traffic = db.get_recent_traffic(limit=100)
    return jsonify(traffic)


@app.route("/api/protocols", methods=["GET"])
def protocol_statistics():
    protocols = db.get_protocol_statistics()
    return jsonify(protocols)


if __name__ == "__main__":
    app.run(debug=True)
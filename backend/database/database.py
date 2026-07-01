import sqlite3
from datetime import datetime
import json


class IDSDatabase:

    def __init__(self, db_path="ids_logs.db"):

        self.db_path = db_path

        self.create_tables()

    def connect(self):

        return sqlite3.connect(self.db_path)

    def create_tables(self):

        conn = self.connect()

        cursor = conn.cursor()

        # TRAFFIC LOGS TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,
            dst_ip TEXT,

            src_port INTEGER,
            dst_port INTEGER,

            protocol TEXT,

            packet_count INTEGER,
            byte_count INTEGER,

            packet_rate REAL,
            byte_rate REAL,

            flow_duration REAL,

            entropy_score REAL,

            threat_score INTEGER DEFAULT 0,

            raw_data TEXT
        )
        """)

        # ATTACK LOGS TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,
            dst_ip TEXT,

            attack_type TEXT,

            severity TEXT,

            protocol TEXT,

            threat_score INTEGER,

            confidence REAL,

            status TEXT,

            features TEXT
        )
        """)

        # BLOCKED IPS TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ip_address TEXT UNIQUE,

            reason TEXT,

            blocked_at TEXT,

            expires_at TEXT
        )
        """)

        conn.commit()

        conn.close()

        print("[+] Database tables initialized")

    # =========================
    # INSERT TRAFFIC LOG
    # =========================

    def insert_traffic_log(self, data):

        try:

            conn = self.connect()

            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO traffic_logs (

                timestamp,

                src_ip,
                dst_ip,

                src_port,
                dst_port,

                protocol,

                packet_count,
                byte_count,

                packet_rate,
                byte_rate,

                flow_duration,

                entropy_score,

                threat_score,

                raw_data

            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (

                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                data.get("src_ip"),
                data.get("dst_ip"),

                data.get("src_port"),
                data.get("dst_port"),

                data.get("protocol"),

                data.get("packet_count", 0),
                data.get("byte_count", 0),

                data.get("packet_rate", 0),
                data.get("byte_rate", 0),

                data.get("flow_duration", 0),

                data.get("entropy_score", 0),

                data.get("threat_score", 0),

                json.dumps(data)

            ))

            conn.commit()

            conn.close()

        except Exception as e:

            print(f"[DATABASE ERROR] Traffic insert failed: {e}")

    # =========================
    # INSERT ATTACK LOG
    # =========================

    def insert_attack_log(self, attack_data):

        try:

            conn = self.connect()

            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO attack_logs (

                timestamp,

                src_ip,
                dst_ip,

                attack_type,

                severity,

                protocol,

                threat_score,

                confidence,

                status,

                features

            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (

                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                attack_data.get("src_ip"),
                attack_data.get("dst_ip"),

                attack_data.get("attack_type"),

                attack_data.get("severity"),

                attack_data.get("protocol"),

                attack_data.get("threat_score", 0),

                attack_data.get("confidence", 0),

                attack_data.get("status", "detected"),

                json.dumps(attack_data)

            ))

            conn.commit()

            conn.close()

            print(f"[+] Attack logged: {attack_data.get('attack_type')}")

        except Exception as e:

            print(f"[DATABASE ERROR] Attack insert failed: {e}")

    # =========================
    # GET ATTACK HISTORY
    # =========================

    def get_attack_history(self, limit=50):

        conn = self.connect()

        cursor = conn.cursor()

        cursor.execute("""
        SELECT * FROM attack_logs
        ORDER BY id DESC
        LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()

        conn.close()

        return rows

    # =========================
    # GET TRAFFIC STATS
    # =========================

    def get_statistics(self):

        conn = self.connect()

        cursor = conn.cursor()

        stats = {}

        # TOTAL TRAFFIC
        cursor.execute("SELECT COUNT(*) FROM traffic_logs")

        stats["total_traffic_logs"] = cursor.fetchone()[0]

        # TOTAL ATTACKS
        cursor.execute("SELECT COUNT(*) FROM attack_logs")

        stats["total_attacks"] = cursor.fetchone()[0]

        # UNIQUE IPS
        cursor.execute("""
        SELECT COUNT(DISTINCT src_ip)
        FROM traffic_logs
        """)

        stats["unique_source_ips"] = cursor.fetchone()[0]

        # HIGH SEVERITY ATTACKS
        cursor.execute("""
        SELECT COUNT(*)
        FROM attack_logs
        WHERE severity='HIGH'
        """)

        stats["high_severity_attacks"] = cursor.fetchone()[0]

        conn.close()

        return stats

    # =========================
    # BLOCK IP RECORD
    # =========================

    def add_blocked_ip(self, ip_address, reason, expires_at=None):

        try:

            conn = self.connect()

            cursor = conn.cursor()

            cursor.execute("""
            INSERT OR IGNORE INTO blocked_ips (

                ip_address,

                reason,

                blocked_at,

                expires_at

            ) VALUES (?, ?, ?, ?)
            """, (

                ip_address,

                reason,

                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                expires_at

            ))

            conn.commit()

            conn.close()

            print(f"[+] Blocked IP recorded: {ip_address}")

        except Exception as e:

            print(f"[DATABASE ERROR] Blocked IP insert failed: {e}")


# =========================
# TEST DATABASE
# =========================

if __name__ == "__main__":

    db = IDSDatabase()

    # TEST TRAFFIC LOG
    db.insert_traffic_log({

        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",

        "src_port": 50500,
        "dst_port": 53,

        "protocol": "UDP",

        "packet_count": 25,
        "byte_count": 5000,

        "packet_rate": 15,
        "byte_rate": 3000,

        "flow_duration": 2.5,

        "entropy_score": 4.2,

        "threat_score": 10
    })

    # TEST ATTACK LOG
    db.insert_attack_log({

        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",

        "attack_type": "syn_flood",

        "severity": "HIGH",

        "protocol": "TCP",

        "threat_score": 90,

        "confidence": 98.5
    })

    print("\n[+] Attack History:")
    print(db.get_attack_history())

    print("\n[+] Statistics:")
    print(db.get_statistics())

import os
import sqlite3
import requests

from datetime import datetime
from dotenv import load_dotenv

from database.database import IDSDatabase

load_dotenv()


class TelegramAlert:
    def __init__(self):
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.database = IDSDatabase()

    def get_admin_chat_id(self):
        """Get the Telegram destination configured by the administrator."""
        conn = self.database.connect()

        try:
            row = conn.execute(
                """
                SELECT telegram_chat_id
                FROM notification_settings
                WHERE id = 1
                """
            ).fetchone()

            chat_id = row[0] if row else None
            return chat_id.strip() if chat_id else None

        except sqlite3.Error as error:
            print(f"[!] Could not retrieve Telegram Chat ID: {error}")
            return None

        finally:
            conn.close()

    def send_attack_alert(self, attack_data):
        if not self.bot_token:
            print("[!] Telegram alert skipped: bot token is missing")
            return False

        chat_id = self.get_admin_chat_id()

        if not chat_id:
            print("[!] Telegram alert skipped: administrator Chat ID not configured")
            return False

        confidence = float(attack_data.get("confidence", 0) or 0)

        # Support both fractional confidence (0.95) and percentage (95).
        if 0 <= confidence <= 1:
            confidence *= 100

        timestamp = attack_data.get("timestamp") or datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        message = (
            "🚨 AI-POWERED NIDS ALERT 🚨\n\n"
            f"Time: {timestamp}\n\n"
            f"Attack Type: {attack_data.get('attack_type', 'Unknown')}\n"
            f"Severity: {attack_data.get('severity', 'UNKNOWN')}\n"
            f"Protocol: {attack_data.get('protocol', 'N/A')}\n\n"
            f"Source IP: {attack_data.get('src_ip', 'N/A')}\n"
            f"Destination IP: {attack_data.get('dst_ip', 'N/A')}\n\n"
            f"Threat Score: {attack_data.get('threat_score', 0)}\n"
            f"AI Confidence: {confidence:.1f}%\n"
            f"Packet Rate: {attack_data.get('packet_rate', 0)}\n"
            f"Byte Rate: {attack_data.get('byte_rate', 0)}\n"
            f"Response Status: {attack_data.get('status', 'N/A')}"
        )

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        try:
            response = requests.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": message,
                },
                timeout=10,
            )
            response.raise_for_status()

            result = response.json()

            if not result.get("ok"):
                print("[!] Telegram API did not accept the alert")
                return False

            print("[+] Telegram alert sent to the configured administrator")
            return True

        except (requests.RequestException, ValueError) as error:
            print(
                f"[!] Telegram alert failed: "
                f"{type(error).__name__}: {error}"
            )
            return False
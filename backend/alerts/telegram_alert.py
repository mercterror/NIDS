import os
import requests

from datetime import datetime
from dotenv import load_dotenv


# =========================
# LOAD ENV VARIABLES
# =========================

load_dotenv()


class TelegramAlert:

    def __init__(self):

        # =========================
        # TELEGRAM CONFIG
        # =========================

        self.bot_token = os.getenv(
            "TELEGRAM_BOT_TOKEN"
        )

        self.chat_id = os.getenv(
            "TELEGRAM_CHAT_ID"
        )

        # =========================
        # TELEGRAM API URL
        # =========================

        self.base_url = (
            f"https://api.telegram.org/bot"
            f"{self.bot_token}/sendMessage"
        )

    # =========================
    # SEND IDS ALERT
    # =========================

    def send_attack_alert(self, attack_data):

        try:

            # =========================
            # EXTRACT DATA
            # =========================

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            src_ip = attack_data.get(
                "src_ip",
                "unknown"
            )

            dst_ip = attack_data.get(
                "dst_ip",
                "unknown"
            )

            protocol = attack_data.get(
                "protocol",
                "unknown"
            )

            attack_type = attack_data.get(
                "attack_type",
                "unknown"
            )

            severity = attack_data.get(
                "severity",
                "LOW"
            )

            threat_score = attack_data.get(
                "threat_score",
                0
            )

            confidence = attack_data.get(
                "confidence",
                0
            )

            packet_rate = attack_data.get(
                "packet_rate",
                0
            )

            byte_rate = attack_data.get(
                "byte_rate",
                0
            )

            # =========================
            # BUILD MESSAGE
            # =========================

            message = (

                "🚨 AI-POWERED IDS ALERT 🚨\n\n"

                f"Time: {timestamp}\n\n"

                f"Attack Type: {attack_type}\n"

                f"Severity: {severity}\n"

                f"Protocol: {protocol}\n\n"

                f"Source IP: {src_ip}\n"

                f"Destination IP: {dst_ip}\n\n"

                f"Threat Score: {threat_score}\n"

                f"AI Confidence: {confidence}%\n\n"

                f"Packet Rate: {packet_rate}\n"

                f"Byte Rate: {byte_rate}\n"
            )

            # =========================
            # TELEGRAM PAYLOAD
            # =========================

            payload = {

                "chat_id": self.chat_id,

                "text": message
            }

            # =========================
            # SEND ALERT
            # =========================

            response = requests.post(

                self.base_url,

                data=payload,

                timeout=10
            )

            # =========================
            # RESPONSE STATUS
            # =========================

            if response.status_code == 200:

                print(
                    "[+] Telegram alert sent"
                )

            else:

                print(
                    f"[TELEGRAM ERROR] "
                    f"{response.status_code}"
                )

                print(response.text)

        except Exception as e:

            print(
                f"[TELEGRAM EXCEPTION] {e}"
            )
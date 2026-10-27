import os
import sqlite3
import smtplib

from email.message import EmailMessage
from dotenv import load_dotenv

from database.database import IDSDatabase

load_dotenv()


class EmailAlert:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 465

        # Sender credentials stay on the backend.
        self.sender_email = os.getenv("EMAIL_SENDER")
        self.sender_password = os.getenv("EMAIL_APP_PASSWORD")

        self.database = IDSDatabase()

    def get_admin_email(self):
        """Return the alert recipient chosen in Settings."""
        conn = self.database.connect()

        try:
            row = conn.execute(
                """
                SELECT alert_email
                FROM notification_settings
                WHERE id = 1
                """
            ).fetchone()

            email = row[0] if row else None
            return email.strip() if email else None

        except sqlite3.Error as error:
            print(f"[!] Could not retrieve alert email: {error}")
            return None

        finally:
            conn.close()

    def send_attack_alert(self, attack_data):
        if not self.sender_email or not self.sender_password:
            print("[!] Email alert skipped: sender configuration missing")
            return False

        receiver_email = self.get_admin_email()

        if not receiver_email:
            print("[!] Email alert skipped: alert recipient not configured")
            return False

        try:
            confidence = float(
                attack_data.get("confidence", 0) or 0
            )

            # Support confidence values expressed as 0.95 or 95.
            if 0 <= confidence <= 1:
                confidence *= 100

            message = EmailMessage()
            message["Subject"] = (
                f"NIDS Alert: {attack_data.get('severity', 'UNKNOWN')} "
                f"- {attack_data.get('attack_type', 'Unknown Attack')}"
            )
            message["From"] = self.sender_email
            message["To"] = receiver_email

            message.set_content(
                f"""AI-POWERED IDS ALERT

Time: {attack_data.get('timestamp', 'N/A')}

Attack Type: {attack_data.get('attack_type', 'Unknown')}
Severity: {attack_data.get('severity', 'UNKNOWN')}
Protocol: {attack_data.get('protocol', 'N/A')}

Source IP: {attack_data.get('src_ip', 'N/A')}
Destination IP: {attack_data.get('dst_ip', 'N/A')}

Threat Score: {attack_data.get('threat_score', 0)}
AI Confidence: {confidence:.1f}%

Response Status: {attack_data.get('status', 'N/A')}
"""
            )

            print("[*] Connecting to Gmail SMTP using SSL...")

            with smtplib.SMTP_SSL(
                self.smtp_server,
                self.smtp_port,
                timeout=20,
            ) as server:
                server.login(
                    self.sender_email,
                    self.sender_password,
                )
                server.send_message(message)

            print("[+] Email alert sent successfully")
            return True

        except Exception as error:
            print(
                f"[!] Email alert failed: "
                f"{type(error).__name__}: {error}"
            )
            return False
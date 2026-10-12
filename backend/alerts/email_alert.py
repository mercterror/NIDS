import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()


class EmailAlert:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 465

        self.sender_email = os.getenv("EMAIL_SENDER")
        self.sender_password = os.getenv("EMAIL_APP_PASSWORD")
        self.receiver_email = os.getenv("EMAIL_RECEIVER")

    def send_attack_alert(self, attack_data):
        if not all([
            self.sender_email,
            self.sender_password,
            self.receiver_email,
        ]):
            print("[!] Email alert skipped: email configuration missing")
            return False

        message = EmailMessage()
        message["Subject"] = (
            f"NIDS Alert: {attack_data.get('severity', 'UNKNOWN')} "
            f"- {attack_data.get('attack_type', 'Unknown Attack')}"
        )
        message["From"] = self.sender_email
        message["To"] = self.receiver_email

        message.set_content(
            f"""AI-POWERED IDS ALERT

Time: {attack_data.get('timestamp', 'N/A')}

Attack Type: {attack_data.get('attack_type', 'Unknown')}
Severity: {attack_data.get('severity', 'UNKNOWN')}
Protocol: {attack_data.get('protocol', 'N/A')}

Source IP: {attack_data.get('src_ip', 'N/A')}
Destination IP: {attack_data.get('dst_ip', 'N/A')}

Threat Score: {attack_data.get('threat_score', 0)}
AI Confidence: {float(attack_data.get('confidence', 0)) * 100:.1f}%

Response Status: {attack_data.get('status', 'N/A')}
"""
        )

        try:
            print("[*] Connecting to Gmail SMTP using SSL...")

            with smtplib.SMTP_SSL(
                self.smtp_server,
                self.smtp_port,
                timeout=20,
            ) as server:
                print("[+] SSL connection established")

                server.ehlo()
                print("[*] Authenticating with Gmail...")

                server.login(
                    self.sender_email,
                    self.sender_password,
                )
                print("[+] Gmail authentication successful")

                server.send_message(message)
                print("[+] Email message accepted by Gmail")

            print("[+] Email alert sent")
            return True

        except Exception as error:
            print(
                f"[!] Email alert failed: "
                f"{type(error).__name__}: {error}"
            )
            return False
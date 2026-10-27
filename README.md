# Network Intrusion Detection and Prevention System (NIDS)

An AI-powered Network Intrusion Detection and Prevention System that monitors network traffic, identifies suspicious activity using machine learning and rule-based detection, and supports automated IP blocking through Windows Firewall.

## Features

- **Live Traffic Monitoring:** Captures and monitors network packets using Scapy.
- **Machine Learning Detection:** Uses a trained Random Forest model to classify network traffic.
- **Rule-Based Detection:** Calculates threat scores and applies threshold-based response decisions.
- **IP Blocking:** Supports IPv4 blocking through Windows Firewall with safeguards against blocking local IP addresses.
- **Security Alerts:** Sends email and Telegram notifications for detected threats.
- **Database Logging:** Stores user accounts, traffic records, and security events using SQLite.
- **Authentication:** Provides authenticated access to the NIDS dashboard and administrative settings.
- **Interactive Dashboard:** Displays traffic analytics, alerts, blocked entities, and system settings through a React.js frontend.
- **Safe Testing Mode:** Uses simulated response actions by default to reduce the risk of disrupting network connectivity.

## Technology Stack

**Backend:** Python, Flask, Scapy, pandas, NumPy, scikit-learn.

**Frontend:** React.js, JavaScript, Vite.

**Machine Learning:** Random Forest classifier.

**Database:** SQLite.

**Security and Notifications:** Windows Firewall, JWT authentication, email, and Telegram Bot API.

## Project Structure

```text
NIDS/
├── backend/
│   ├── alerts/
│   ├── database/
│   ├── dataset/
│   ├── ml/
│   │   └── models/
│   ├── response_engine/
│   ├── server/
│   ├── sniffer/
│   └── test_*.py
├── frontend/
│   ├── public/
│   └── src/
├── requirements.txt
└── README.md
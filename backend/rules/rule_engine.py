from datetime import datetime


class RuleEngine:

    def __init__(self):

        # ==========================
        # SYN FLOOD
        # ==========================

        self.syn_threshold = 150
        self.syn_ratio = 0.90

        # ==========================
        # PORT SCAN
        # ==========================

        self.portscan_ports = 30

        # ==========================
        # ICMP FLOOD
        # ==========================

        self.icmp_rate = 500

        # ==========================
        # DNS ABUSE
        # ==========================

        self.dns_queries = 50

        # ==========================
        # BRUTE FORCE
        # ==========================

        self.failed_connections = 25

        self.bruteforce_ports = [
            21,
            22,
            23,
            25,
            110,
            143,
            3389
        ]

        # ==========================
        # DATA EXFILTRATION
        # ==========================

        self.exfiltration_bytes = 30 * 1024 * 1024

    # ======================================================
    # MAIN DETECTION
    # ======================================================

    def detect(self, features):

        result = {

            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "attack_detected": False,

            "attack_type": "normal",

            "severity": "LOW",

            "threat_score": 0,

            "confidence": 0
        }

        # ==========================================
        # BASIC VALIDATION
        # ==========================================

        src = features.get("src_ip")

        if src is None:
            return result

        if src.startswith("127."):
            return result

        if src.startswith("224."):
            return result

        if src.startswith("239."):
            return result

        if src == "0.0.0.0":
            return result

        # Ignore tiny flows

        if features.get("packet_count", 0) < 5:
            return result

        if features.get("flow_duration", 0) < 2:
            return result

        # ===================================================
        # SYN FLOOD
        # ===================================================

        if (

            features.get("syn_flag_count", 0) > self.syn_threshold

            and

            features.get("ack_flag_count", 0) < 10

            and

            features.get("syn_ratio", 0) > self.syn_ratio

            and

            features.get("packet_count", 0) > 150

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "syn_flood",

                "severity": "CRITICAL",

                "threat_score": 98,

                "confidence": 98

            })

            return result

        # ===================================================
        # PORT SCAN
        # ===================================================

        if (

            features.get("unique_dst_ports", 0) > self.portscan_ports

            and

            features.get("packet_count", 0) < 300

            and

            features.get("average_packet_size", 0) < 150

            and

            features.get("flow_duration", 0) < 30

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "port_scan",

                "severity": "HIGH",

                "threat_score": 90,

                "confidence": 94

            })

            return result

        # ===================================================
        # ICMP FLOOD
        # ===================================================

        if (

            features.get("protocol") == "ICMP"

            and

            features.get("packet_rate", 0) > self.icmp_rate

            and

            features.get("packet_count", 0) > 300

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "icmp_flood",

                "severity": "HIGH",

                "threat_score": 90,

                "confidence": 95

            })

            return result

        # ===================================================
        # SSH / FTP / TELNET BRUTE FORCE
        # ===================================================

        if (

            features.get("failed_connections", 0)

            > self.failed_connections

            and

            features.get("dst_port")

            in self.bruteforce_ports

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "brute_force",

                "severity": "HIGH",

                "threat_score": 88,

                "confidence": 92

            })

            return result

        # ===================================================
        # DNS ABUSE
        # ===================================================

        if (

            features.get("dst_port") == 53

            and

            features.get("dns_query_count", 0)

            > self.dns_queries

            and

            features.get("packet_rate", 0) > 100

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "dns_abuse",

                "severity": "MEDIUM",

                "threat_score": 75,

                "confidence": 85

            })

            return result

        # ===================================================
        # DATA EXFILTRATION
        # ===================================================

        if (

            features.get("byte_count", 0)

            > self.exfiltration_bytes

            and

            features.get("flow_duration", 0) > 60

            and

            features.get("average_packet_size", 0) > 1000

            and

            features.get("packet_count", 0) > 500

        ):

            result.update({

                "attack_detected": True,

                "attack_type": "data_exfiltration",

                "severity": "CRITICAL",

                "threat_score": 95,

                "confidence": 93

            })

            return result

        return result

    # ======================================================
    # DISPLAY ALERT
    # ======================================================

    def display_alert(self, result):

        if not result["attack_detected"]:
            return

        print("\n")

        print("=" * 70)

        print("RULE ENGINE DETECTED ATTACK")

        print("=" * 70)

        print(f"Timestamp      : {result['timestamp']}")

        print(f"Attack         : {result['attack_type']}")

        print(f"Severity       : {result['severity']}")

        print(f"Threat Score   : {result['threat_score']}")

        print(f"Confidence     : {result['confidence']}%")

        print("=" * 70)

    # ======================================================
    # TEST
    # ======================================================

    def test(self):

        sample = {

            "src_ip": "192.168.1.10",

            "protocol": "TCP",

            "packet_count": 250,

            "flow_duration": 5,

            "syn_flag_count": 220,

            "ack_flag_count": 2,

            "syn_ratio": 0.97,

            "average_packet_size": 64,

            "unique_dst_ports": 1,

            "packet_rate": 120,

            "byte_count": 500000,

            "dst_port": 80,

            "failed_connections": 0,

            "dns_query_count": 0

        }

        result = self.detect(sample)

        self.display_alert(result)


if __name__ == "__main__":

    RuleEngine().test()
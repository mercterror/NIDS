from datetime import datetime


class RuleEngine:

    def __init__(self):

        # =========================
        # ATTACK THRESHOLDS
        # =========================

        self.syn_flood_threshold = 100
        self.icmp_flood_threshold = 200
        self.port_scan_threshold = 20
        self.dns_abuse_threshold = 100
        self.arp_spoof_threshold = 50
        self.bruteforce_threshold = 40

        self.ddos_packet_rate = 1000
        self.ddos_byte_rate = 500000

        self.data_exfiltration_rate = 1000000
        self.data_exfiltration_duration = 60

    # =========================
    # MAIN RULE ENGINE
    # =========================

    def detect(self, features):

        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_detected": False,
            "attack_type": "normal",
            "severity": "LOW",
            "threat_score": 0,
            "confidence": 0
        }

        # =====================================================
        # SYN FLOOD
        # =====================================================

        if (
            features.get("syn_flag_count", 0) > self.syn_flood_threshold
            and
            features.get("ack_flag_count", 0) < 5
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "syn_flood",
                "severity": "CRITICAL",
                "threat_score": 95,
                "confidence": 98
            })

        # =====================================================
        # ICMP FLOOD
        # =====================================================

        elif (
            features.get("protocol") == "ICMP"
            and
            features.get("packet_rate", 0) > self.icmp_flood_threshold
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "icmp_flood",
                "severity": "HIGH",
                "threat_score": 90,
                "confidence": 95
            })

        # =====================================================
        # PORT SCAN
        # =====================================================

        elif (
            features.get("unique_dst_ports", 0)
            > self.port_scan_threshold
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "port_scan",
                "severity": "HIGH",
                "threat_score": 88,
                "confidence": 92
            })

        # =====================================================
        # DNS ABUSE
        # =====================================================

        elif (
            features.get("dns_query_count", 0)
            > self.dns_abuse_threshold
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "dns_abuse",
                "severity": "MEDIUM",
                "threat_score": 75,
                "confidence": 85
            })

        # =====================================================
        # ARP SPOOFING
        # =====================================================

        elif (
            features.get("arp_requests", 0)
            > self.arp_spoof_threshold
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "arp_spoofing",
                "severity": "HIGH",
                "threat_score": 85,
                "confidence": 90
            })

        # =====================================================
        # BRUTE FORCE
        # =====================================================

        elif (
            features.get("failed_connections", 0)
            > self.bruteforce_threshold
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "brute_force",
                "severity": "HIGH",
                "threat_score": 87,
                "confidence": 91
            })

        # =====================================================
        # DDoS
        # =====================================================

        elif (
            features.get("packet_rate", 0)
            > self.ddos_packet_rate
            and
            features.get("byte_rate", 0)
            > self.ddos_byte_rate
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "ddos",
                "severity": "CRITICAL",
                "threat_score": 99,
                "confidence": 96
            })

        # =====================================================
        # DATA EXFILTRATION
        # =====================================================

        elif (
            features.get("byte_rate", 0)
            > self.data_exfiltration_rate
            and
            features.get("flow_duration", 0)
            > self.data_exfiltration_duration
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "data_exfiltration",
                "severity": "CRITICAL",
                "threat_score": 97,
                "confidence": 94
            })

        # =====================================================
        # SUSPICIOUS LARGE FLOW
        # =====================================================

        elif (
            features.get("packet_count", 0) > 5000
            and
            features.get("flow_duration", 0) < 5
        ):

            result.update({
                "attack_detected": True,
                "attack_type": "suspicious_large_flow",
                "severity": "MEDIUM",
                "threat_score": 70,
                "confidence": 82
            })

        return result

    # =========================
    # DISPLAY ALERT
    # =========================

    def display_alert(self, result):

        if not result["attack_detected"]:
            return

        print("\n")
        print("=" * 70)
        print("           RULE ENGINE ATTACK DETECTED")
        print("=" * 70)

        print(f"Timestamp      : {result['timestamp']}")
        print(f"Attack Type    : {result['attack_type']}")
        print(f"Severity       : {result['severity']}")
        print(f"Threat Score   : {result['threat_score']}")
        print(f"Confidence     : {result['confidence']} %")

        print("=" * 70)

    # =========================
    # TEST RULE ENGINE
    # =========================

    def test(self):

        sample = {

            "protocol": "TCP",

            "packet_rate": 1500,

            "byte_rate": 700000,

            "flow_duration": 2,

            "packet_count": 600,

            "unique_dst_ports": 50,

            "dns_query_count": 2,

            "arp_requests": 0,

            "failed_connections": 0,

            "syn_flag_count": 180,

            "ack_flag_count": 1

        }

        result = self.detect(sample)

        self.display_alert(result)


if __name__ == "__main__":

    RuleEngine().test()
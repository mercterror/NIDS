from scapy import packet
import traceback
from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Ether,
    Raw,
)
from datetime import datetime
from sniffer.flow_analyzer import FlowAnalyzer
from detection_engine.detector import analyze_packet
from integration.final_decision import make_final_decision

from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor
from response_engine.response_engine import ResponseEngine
from rules.rule_engine import RuleEngine

from database.database import IDSDatabase
from alerts.telegram_alert import TelegramAlert
from alerts.email_alert import EmailAlert

class PacketSniffer:

    def __init__(self, interface=None, dry_run=True):
        self.interface = interface
        self.flow_analyzer = FlowAnalyzer()
        self.database = IDSDatabase()
        self.telegram_alert = TelegramAlert()
        self.alerts_enabled = True
        self.email_alert = EmailAlert()
        self.rule_engine = RuleEngine()

        self.adapter = TrafficAdapter()
        self.feature_extractor = FeatureExtractor()
        self.predictor = NIDSPredictor()

        self.response_engine = ResponseEngine(dry_run=dry_run)

        mode = "DRY RUN" if dry_run else "REAL FIREWALL ACTIONS"
        print(f"[+] Response mode: {mode}")


    def get_protocol_name(self, proto_number):
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        return protocols.get(proto_number, "OTHER")

    def parse_packet(self, packet):
        try:
            packet_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "packet_size": len(packet),
                "ttl": None,
                "tcp_flags": None,
                "icmp_type": None,
                "src_mac": None,
                "dst_mac": None
            }

            # =========================
            # ETHERNET LAYER
            # =========================
            if packet.haslayer(Ether):
                packet_data["src_mac"] = packet[Ether].src
                packet_data["dst_mac"] = packet[Ether].dst

            # =========================
            # IP LAYER
            # =========================
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_data["src_ip"] = ip_layer.src
                packet_data["dst_ip"] = ip_layer.dst
                packet_data["ttl"] = ip_layer.ttl
                packet_data["protocol"] = self.get_protocol_name(ip_layer.proto)

            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                packet_data["src_ip"] = ipv6_layer.src
                packet_data["dst_ip"] = ipv6_layer.dst
                packet_data["ttl"] = ipv6_layer.hlim
                packet_data["protocol"] = self.get_protocol_name(ipv6_layer.nh)

            # =========================
            # TCP LAYER
            # =========================
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data["src_port"] = tcp_layer.sport
                packet_data["dst_port"] = tcp_layer.dport
                packet_data["tcp_flags"] = str(tcp_layer.flags)

            # =========================
            # UDP LAYER
            # =========================
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data["src_port"] = udp_layer.sport
                packet_data["dst_port"] = udp_layer.dport

            # =========================
            # ICMP LAYER
            # =========================
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_data["icmp_type"] = icmp_layer.type

            # Display formatted packet (skipping None/blank values)
            self.display_packet(packet_data)
            
            # --- Flow analysis engine calls (Cleaned spaces) ---
            flow_features = self.flow_analyzer.update_flow(packet_data)
            
            self.flow_analyzer.display_flow(flow_features)

            
            # Save the current flow statistics to the database.
            flow_key = flow_features["flow_key"]

            traffic_log = {
                "src_ip": flow_key[0],
                "dst_ip": flow_key[1],
                "src_port": flow_key[2],
                "dst_port": flow_key[3],
                "protocol": flow_key[4],
                "packet_count": flow_features["packet_count"],
                "byte_count": flow_features["byte_count"],
                "packet_rate": flow_features["packet_rate"],
                "byte_rate": flow_features["byte_rate"],
                "flow_duration": flow_features["duration"],
                "entropy_score": flow_features["entropy_score"],
                "threat_score": 0
            }

            traffic_record_id = self.database.insert_traffic_log(traffic_log)


            adapted_packet = self.adapter.adapt_packet(packet_data)
            adapted_flow = self.adapter.adapt_flow(flow_features)

            features = self.feature_extractor.extract_features(
                adapted_packet,
                adapted_flow
            )

            self.feature_extractor.display_features(features)
            ai_result = self.predictor.predict(features)
            flow_rule_result = self.rule_engine.detect(features)

            if flow_rule_result["attack_detected"]:
                print(
                    f"[FLOW RULE] {flow_rule_result['attack_type']} | "
                    f"Score: {flow_rule_result['threat_score']}"
                )
            
            print("\n" + "=" * 65)
            print("AI DETECTION")
            print("=" * 65)
            print(f"Prediction : {ai_result['label']}")
            print(f"Confidence : {ai_result['confidence']:.2f}")
            print("=" * 65)

            rule_result = analyze_packet(adapted_packet)

            if flow_rule_result["attack_detected"]:
                rule_result = {
                    **rule_result,
                    "score": max(
                        rule_result["score"],
                        flow_rule_result["threat_score"]
                    ),
                    "is_suspicious": True,
                    "reasons": [
                        *rule_result["reasons"],
                        flow_rule_result["attack_type"]
                    ]
                }

            decision = make_final_decision(
                rule_result,
                ai_result
            )

            self.database.update_traffic_threat_score(
            traffic_record_id,
            rule_result["score"]
)

            
            response_packet = {
                "source_ip": packet_data["src_ip"],
                "source_mac": packet_data["src_mac"]
            }

            response_result = self.response_engine.handle_decision(
                decision,
                response_packet
            )

            print("\n" + "=" * 65)
            print("RESPONSE ENGINE")
            print("=" * 65)
            print(f"Action       : {response_result['action']}")
            print(f"Status       : {response_result['status']}")

            if "block_success" in response_result:
                print(f"Block success: {response_result['block_success']}")

            print("=" * 65)


            print("\n" + "=" * 65)
            print("FINAL DETECTION")
            print("=" * 65)

            print(f"Rule Score : {rule_result['score']}")
            print(f"Suspicious : {rule_result['is_suspicious']}")
            print(f"Reasons    : {rule_result['reasons']}")
            print(f"AI Result  : {ai_result['label']}")
            print(f"Confidence: {ai_result['confidence']:.2f}")
            print(f"Verdict    : {decision['final_verdict']}")
            print(f"Action     : {decision['action']}")

            print("=" * 65)

            
            
            # Log malicious final decisions to the database.
            if decision["final_verdict"] == "MALICIOUS":
                threat_score = rule_result["score"]

                attack_log = {
                    "src_ip": packet_data["src_ip"],
                    "timestamp": packet_data["timestamp"],
                    "packet_rate": flow_features["packet_rate"],
                    "byte_rate": flow_features["byte_rate"],
                    "dst_ip": packet_data["dst_ip"],
                    "attack_type": (
                        ai_result["label"]
                        if ai_result["label"].lower() != "normal"
                        else (
                            ", ".join(rule_result["reasons"])
                            or "Rule-based detection"
                        )
                    ),
                    "severity": (
                        "HIGH" if threat_score >= 50 else "MEDIUM"
                    ),
                    "protocol": packet_data["protocol"],
                    "threat_score": threat_score,
                    "confidence": ai_result["confidence"],
                    "status": response_result["status"],
                    "rule_result": rule_result,
                    "ai_result": ai_result,
                    "final_decision": decision
                }

                self.database.insert_attack_log(attack_log)
                if self.alerts_enabled:
                    self.telegram_alert.send_attack_alert(attack_log)
                    self.email_alert.send_attack_alert(attack_log)



            self.flow_analyzer.expire_old_flows()

            return packet_data, flow_features

        except Exception as e:
            print(f"[ERROR] Packet parsing failed: {e}")
            traceback.print_exc()
            return

    def display_packet(self, data):
        print("\n" + "=" * 50)
        
        for key, value in data.items():
            # Strict filtering out of Python None and string "None"
            if value is not None and str(value).strip() not in ("None", ""):
                display_name = key.replace("_", " ").title()
                display_name = (display_name
                                .replace("Ip", "IP")
                                .replace("Mac", "MAC")
                                .replace("Ttl", "TTL")
                                .replace("Icmp", "ICMP")
                                .replace("Tcp", "TCP"))
                
                print(f"{display_name:<16}: {value}")
                
        print("=" * 50)

    def start(self):
        print("[+] Starting Packet Sniffer...")
        print(f"[+] Interface: {self.interface if self.interface else 'All / Default'}")

        sniff(
            iface=self.interface,
           filter="tcp or udp or icmp",
            prn=self.parse_packet,
            store=False
        )


if __name__ == "__main__":
    import os

    wifi_interface = r"\Device\NPF_{2C13D9CE-1493-44FD-B62F-4F8B4A637796}"

    # Real firewall actions require explicit opt-in.
    real_blocking = os.environ.get("NIDS_REAL_BLOCKING", "").strip().lower() == "true"

    if real_blocking:
        print("[!] REAL IP BLOCKING ENABLED.")
        print("[!] Run only with administrator privileges and on a network you are authorized to monitor.")
    else:
        print("[+] Safe mode enabled. Firewall actions are simulated.")

    sniffer = PacketSniffer(
        interface=wifi_interface,
        dry_run=not real_blocking
    )
    sniffer.start()

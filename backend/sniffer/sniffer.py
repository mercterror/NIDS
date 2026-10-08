from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from datetime import datetime
from sniffer.flow_analyzer import FlowAnalyzer
from detection_engine.detector import analyze_packet
from integration.final_decision import make_final_decision

from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor

class PacketSniffer:

    def __init__(self, interface=None):
        self.interface = interface
        self.flow_analyzer = FlowAnalyzer()

        self.adapter = TrafficAdapter()
        self.feature_extractor = FeatureExtractor()
        self.predictor = NIDSPredictor()

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

            adapted_packet = self.adapter.adapt_packet(packet_data)
            adapted_flow = self.adapter.adapt_flow(flow_features)

            features = self.feature_extractor.extract_features(
                adapted_packet,
                adapted_flow
            )

            self.feature_extractor.display_features(features)
            ai_result = self.predictor.predict(features)
            
            print("\n" + "=" * 65)
            print("AI DETECTION")
            print("=" * 65)
            print(f"Prediction : {ai_result['label']}")
            print(f"Confidence : {ai_result['confidence']:.2f}")
            print("=" * 65)

            rule_result = analyze_packet(adapted_packet)

            decision = make_final_decision(
                rule_result,
                ai_result
            )

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

            self.flow_analyzer.expire_old_flows()

            return packet_data, flow_features

        except Exception as e:
            print(f"[ERROR] Packet parsing failed: {e}")
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
    sniffer = PacketSniffer(interface=None)
    sniffer.start()
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from datetime import datetime

from backend.sniffer.flow_analyzer import FlowAnalyzer
from backend.ml.dataset_generator import DatasetGenerator
from backend.database.database import IDSDatabase
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.realtime_detector import RealtimeDetector


class PacketSniffer:

    def __init__(self, interface=None):
        self.interface = interface

        # FLOW ANALYZER
        self.flow_analyzer = FlowAnalyzer()

        # FEATURE EXTRACTION ENGINE
        self.feature_extractor = FeatureExtractor()

        # DATASET CSV LOGGER
        self.dataset_generator = DatasetGenerator()

        # SQLITE DATABASE
        self.db = IDSDatabase()


        self.detector = RealtimeDetector()


    # PROTOCOL NAME MAPPING


    def get_protocol_name(self, proto_number):
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        return protocols.get(proto_number, "OTHER")


    # PACKET PARSER
  

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

           
            # ETHERNET LAYER
           
            if packet.haslayer(Ether):
                packet_data["src_mac"] = packet[Ether].src
                packet_data["dst_mac"] = packet[Ether].dst

            # IP LAYER

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_data["src_ip"] = ip_layer.src
                packet_data["dst_ip"] = ip_layer.dst
                packet_data["ttl"] = ip_layer.ttl
                packet_data["protocol"] = self.get_protocol_name(ip_layer.proto)

            
            # TCP LAYER
            

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data["src_port"] = tcp_layer.sport
                packet_data["dst_port"] = tcp_layer.dport
                packet_data["tcp_flags"] = str(tcp_layer.flags)

          
            # UDP LAYER

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data["src_port"] = udp_layer.sport
                packet_data["dst_port"] = udp_layer.dport

            # ICMP LAYER

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_data["icmp_type"] = icmp_layer.type


            # DISPLAY RAW PACKET

            self.display_packet(packet_data)


            # FLOW ANALYSIS

            flow_features = self.flow_analyzer.update_flow(packet_data)

            # ONLY PROCESS VALID FLOWS
            if flow_features:

                # DISPLAY FLOW
                self.flow_analyzer.display_flow(flow_features)

                # =========================
                # FEATURE EXTRACTION
                # =========================

                ml_features = self.feature_extractor.extract_features(
                    packet_data,
                    flow_features
                )

                # DISPLAY FEATURES
                self.feature_extractor.display_features(ml_features)

                # =========================
                # SAVE TO CSV DATASET
                # =========================

                self.dataset_generator.save_feature_row(ml_features)

                # =========================
                # SAVE TO SQLITE DATABASE
                # =========================

                self.db.insert_traffic_log(ml_features)

                # =========================
                # telegram alert
                # =========================

                self.detector.detect_attack(ml_features)

            # =========================
            # EXPIRE OLD FLOWS
            # =========================

            self.flow_analyzer.expire_old_flows()

            # IMPORTANT:
            # RETURN NOTHING
            # Prevent Scapy auto-printing dicts
            return

        except Exception as e:
            print(f"[ERROR] Packet parsing failed: {e}")
            return


    # DISPLAY PACKET


    def display_packet(self, data):
        print("\n" + "=" * 50)

        for key, value in data.items():
            # SKIP EMPTY VALUES
            if value is not None and str(value).strip() not in ("None", ""):
                display_name = key.replace("_", " ").title()
                display_name = (
                    display_name
                    .replace("Ip", "IP")
                    .replace("Mac", "MAC")
                    .replace("Ttl", "TTL")
                    .replace("Icmp", "ICMP")
                    .replace("Tcp", "TCP")
                )
                print(f"{display_name:<20}: {value}")

        print("=" * 50)

    
    # START SNIFFER
    

    def start(self):
        print("[+] Starting Packet Sniffer...")
        print(f"[+] Interface: {self.interface if self.interface else 'All / Default'}")

        sniff(
            iface=self.interface,
            filter="tcp or udp or icmp",
            prn=self.parse_packet,
            store=False
        )



# MAIN


if __name__ == "__main__":
    sniffer = PacketSniffer(interface=None)
    sniffer.start()
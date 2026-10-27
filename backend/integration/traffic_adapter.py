class TrafficAdapter:

    def adapt_packet(self, packet):
        return {
            "source_ip": packet.get("source_ip", packet.get("src_ip")),
            "destination_ip": packet.get("destination_ip", packet.get("dst_ip")),
            "source_port": packet.get("source_port", packet.get("src_port")),
            "destination_port": packet.get("destination_port", packet.get("dst_port")),
            "protocol": packet["protocol"],
            "packet_size": packet["packet_size"],
            "ttl": packet["ttl"],
            "tcp_flags": packet["tcp_flags"],
            "icmp_type": packet["icmp_type"]
        }

    def adapt_flow(self, flow):
        return {
            "duration": flow["duration"],
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "packet_rate": flow["packet_rate"],
            "byte_rate": flow["byte_rate"],
            "average_packet_size": flow["average_packet_size"],
            "unique_src_ports": flow["unique_src_ports"],
            "unique_dst_ports": flow["unique_dst_ports"],
            "entropy_score": flow["entropy_score"],
            "avg_inter_arrival": flow["avg_inter_arrival"],
            "idle_time": flow["idle_time"],
            "syn_flag_count": flow["syn_flag_count"],
            "ack_flag_count": flow["ack_flag_count"],
            "fin_flag_count": flow["fin_flag_count"],
            "rst_flag_count": flow["rst_flag_count"],
            "psh_flag_count": flow["psh_flag_count"],
            "urg_flag_count": flow["urg_flag_count"]
        }
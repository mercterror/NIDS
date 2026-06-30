from dataclasses import dataclass,field 
from datatime import datetime
from typing import Dict, Optional

#Creating firstc class Packet with all the data members and their types
@dataclass
class Packet:
    src_ip: str
    dest_ip: str
    src_port: int 
    dest_port: int
    protocol: str
    packet_size: int
    ttl: int
    tcp_flags: Optional[str]
    src_mac: str
    dest_mac: str

@dataclass
class Flow:
    duration: float
    packet_count: int
    byte_count: int
    packet_per_sec: float
    byte_per_sec: float
    unique_src_port: int
    unique_dest_port: int
    entropy: float
    tcp_flags_count: Dict[str, int]

@dataclass
class Simulation:
    simulation_id: int
    ground_truth: str
    packet: Packet
    flow: Flow
    created_at: datetime = field(default_factory=datetime.now)


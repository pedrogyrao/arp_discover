from .communication_handler import CommunicationHandler
from .packet_parser import PacketParser


def scan(src_mac, src_ip, dst_ip, timeout=0.5):
    packet = PacketParser(
        src_mac=src_mac,
        src_ip=src_ip,
        dst_ip=dst_ip).packet

    handler = CommunicationHandler(packet, timeout=0.5)
    answers = handler.run()
    return answers

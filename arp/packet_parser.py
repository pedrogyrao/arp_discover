import struct
import binascii

from scapy.all import Ether


class PacketParser:
    def __init__(self, src_mac, src_ip, dst_ip):
        self._ether = self._assemble_ether(src_mac)
        self._arp = self._assemble_arp(src_mac, src_ip, dst_ip)
        self.packet = Ether(self._ether + self._arp)

    def _parse_ip(self, ip):
        ip = ip.split('.')
        ip = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip))
        return ip

    def _assemble_ether(self, src_mac):
        dst_mac = 'ff:ff:ff:ff:ff:ff'
        _type = '0806'
        ether_packet = binascii.unhexlify(
            (dst_mac + src_mac + _type).replace(':', ''))
        return ether_packet

    def _assemble_arp(self, src_mac, src_ip, dst_ip):
        hwtype = '0001'
        ptype = '0800'
        hwlen = '06'
        plen = '04'
        op = '0001'
        dst_mac = '00:00:00:00:00:00'

        src_ip = self._parse_ip(src_ip)
        dst_ip = self._parse_ip(dst_ip)

        packet = (hwtype + ptype + hwlen + plen + op +
                src_mac + src_ip + dst_mac + dst_ip)
        packet = packet.replace(':', '')
        packet = binascii.unhexlify(packet)
        return packet

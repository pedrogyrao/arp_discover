import struct

from scapy.data import ETH_P_ALL
from scapy.all import AsyncSniffer
from scapy.arch.pcapdnet import L2pcapSocket


class CommunicationHandler:
    def __init__(self, packet, timeout=0.5):
        self.socket = self._init_socket()
        self.packet = packet
        self.timeout = timeout

        self.hsent = {}
        self.ans = []
        self.notans = len(self.packet)

        self.sniffer = AsyncSniffer()

    def _init_socket(self):
        return L2pcapSocket(promisc=None, iface=None,
                            filter=None, nofilter=0,
                            type=ETH_P_ALL)

    def _send_data(self):
        for p in self.packet:
            self.hsent.setdefault(p.hashret(), []).append(p)
            self.socket.send(p)

    def _process_packet(self, r):
        if r is None:
            return
        ok = False
        h = r.hashret()
        if h in self.hsent:
            hlst = self.hsent[h]
            for i, sentpkt in enumerate(hlst):
                if r.answers(sentpkt):
                    self.ans.append((sentpkt, r))
                    ok = True
                    del hlst[i]
                    self.notans -= 1
                    break
        if self.notans <= 0:
            self.sniffer.stop(join=False)

    def _format_answer(self, ps):
        p1, p2 = [bytes(p) for p in ps]
        ip = '.'.join(f'{c}' for c in p1[-4:])
        mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack(
            "BBBBBB", p2[6:12])
        return ip, mac

    def _format_answers(self):
        self.ans = [self._format_answer(an) for an in self.ans]

    def run(self):
        self.sniffer._run(
            prn=self._process_packet,
            timeout=self.timeout,
            store=False,
            opened_socket=self.socket,
            session=None,
            started_callback=self._send_data
        )
        self._format_answers()
        return self.ans

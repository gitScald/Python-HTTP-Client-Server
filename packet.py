import ipaddress

ENCODING = 'utf-8'
PKT_MIN = 11
PKT_MAX = 1024

PKT_TYPE = ['SYN', 'ACK', 'NAK', 'DATA']

SIZE = {'PKT_TYPE': 1,
        'SEQ_NUM': 4,
        'PEER_IP': 4,
        'PEER_PORT': 2}

class UDPPacket:
    def __init__(self,
                 pkt_type,
                 seq_num,
                 peer_ip,
                 peer_port,
                 data):
        self.pkt_type = pkt_type
        self.seq_num = seq_num
        self.data = data
        self.peer_ip = ipaddress.IPv4Address(peer_ip)
        self.peer_port = peer_port
        self.current = 0

    def __repr__(self):
        return 'TYPE: ' + str(self.pkt_type) + '\r\n'\
               + 'SEQ. NUM: ' + str(self.seq_num) + '\r\n'\
               + 'PEER IP: ' + str(self.peer_ip) + '\r\n'\
               + 'PEER PORT: ' + str(self.peer_port) + '\r\n'\
               + 'PAYLOAD: ' + str(self.data)

    def get_bytes(self, raw, n=PKT_MAX):
        if n == PKT_MAX:
            n = PKT_MAX - self.current
        extract = raw[self.current:(self.current + n)]
        self.current += n

        return extract

    def from_bytes(self, raw):
        if len(raw) < PKT_MIN or len(raw) > PKT_MAX:
            raise ValueError('Invalid packet size: ' + str(len(raw)))

        pkt_type = int.from_bytes(self.get_bytes(raw, SIZE['PKT_TYPE']),
                                  byteorder='big')
        seq_num = int.from_bytes(self.get_bytes(raw, SIZE['SEQ_NUM']),
                                 byteorder='big')
        raw_ip = int.from_bytes(self.get_bytes(raw, SIZE['PEER_IP']), byteorder='big')
        peer_ip = ipaddress.IPv4Address(raw_ip)
        peer_port = int.from_bytes(self.get_bytes(raw, SIZE['PEER_PORT']),
                                   byteorder='big')
        data = self.get_bytes(raw).decode(ENCODING)

        return UDPPacket(pkt_type=pkt_type,
                         seq_num=seq_num,
                         peer_ip=peer_ip,
                         peer_port=peer_port,
                         data=data)

    def to_bytes(self):
        buffer = bytearray()
        buffer.extend(self.pkt_type.to_bytes(SIZE['PKT_TYPE'],
                                             byteorder='big'))
        buffer.extend(self.seq_num.to_bytes(SIZE['SEQ_NUM'],
                                            byteorder='big'))
        buffer.extend(self.peer_ip.packed)
        buffer.extend(self.peer_port.to_bytes(SIZE['PEER_PORT'],
                                              byteorder='big'))
        buffer.extend(bytes(self.data, ENCODING))

        return buffer

p = UDPPacket(4, 72, '192.168.1.1', 80, 'test')
buf = p.to_bytes()
print(p.from_bytes(buf))
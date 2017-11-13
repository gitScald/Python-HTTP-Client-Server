import ipaddress

DIVIDER = '-' * 80
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

    def __repr__(self):
        return 'TYPE: ' + str(self.pkt_type) + '\r\n'\
               + 'SEQ. NUM: ' + str(self.seq_num) + '\r\n'\
               + 'PEER IP: ' + str(self.peer_ip) + '\r\n'\
               + 'PEER PORT: ' + str(self.peer_port) + '\r\n'\
               + 'PAYLOAD: ' + '\r\n' + DIVIDER + '\r\n' + str(self.data)

    @staticmethod
    def from_bytes(raw):
        if len(raw) < PKT_MIN or len(raw) > PKT_MAX:
            raise ValueError('Invalid packet size: ' + str(len(raw)))

        current = 0

        def get_bytes(rw, curr, n=PKT_MAX):
            if n == PKT_MAX:
                n = PKT_MAX - curr
            extract = rw[curr:(curr + n)]

            return extract

        pkt_type = int.from_bytes(get_bytes(raw, current, SIZE['PKT_TYPE']),
                                  byteorder='big')
        current += SIZE['PKT_TYPE']

        seq_num = int.from_bytes(get_bytes(raw, current, SIZE['SEQ_NUM']),
                                 byteorder='big')
        current += SIZE['SEQ_NUM']

        raw_ip = int.from_bytes(get_bytes(raw, current, SIZE['PEER_IP']),
                                byteorder='big')
        current += SIZE['PEER_IP']
        peer_ip = ipaddress.IPv4Address(raw_ip)

        peer_port = int.from_bytes(get_bytes(raw, current, SIZE['PEER_PORT']),
                                   byteorder='big')
        current += SIZE['PEER_PORT']

        data = get_bytes(raw, current).decode(ENCODING)

        return UDPPacket(pkt_type=pkt_type,
                         seq_num=seq_num,
                         peer_ip=peer_ip,
                         peer_port=peer_port,
                         data=data)

    def len(self):
        return len(self.to_bytes())

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

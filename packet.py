PKT_MIN = 11
PKT_MAX = 1024

class UDPPacket:
    def __init__(self, type, seq_num, host_ip, host_port, data):
        self.type = type
        self.seq_num = seq_num
        self.data = data
        self.host_ip = host_ip
        self.host_port = host_port
import logging
import math
import packet
import random
import re
import socket
import time

BUFFER_SIZE = 1024
DIVIDER = '-' * 80
ENCODING = 'utf-8'
HTTP_VERSION = 'HTTP/1.1'
ROUTER_PORT = 3000
SOCK_TIMEOUT = 2
WINDOW_SIZE = 4

CMD = {'GET': 'GET',
       'POST': 'POST'}

DATA = {'FILE': '-f',
        'INLINE': '-d'}

REGEX = {'IP_PORT': r'^(?P<host>((http|https):\/{2})?(?P<ip>(\d{1,3}\.){3}\d{1,3}))(:?(?P<port>\d+)?)',
         'PATH_ARGS': r'(?P<path>\/(\w+\/?)*(\.\w+)?)(\?)?(?P<args>\w+=\w+&?)*$',
         'URL_PORT': r'^(?P<host>((http|https):\/{2})?(w{3}\.)?\w+\.\w+)(:?(?P<port>\d+)?)'}

logging.basicConfig(level=logging.DEBUG,
                    format='(%(asctime)-23s) (%(threadName)-12s) %(message)s')


class Request:
    def __init__(self,
                 rqst_type,
                 host=tuple(),
                 path='/',
                 headers=None,
                 data_type='',
                 data=''):
        self.rqst_line = ''
        self.rqst_type = rqst_type
        self.host = host
        self.path = path
        self.headers = headers
        self.data_type = data_type
        self.data = data
        self.body = ''

        self.init()

    def __repr__(self):
        msg = str(self.rqst_line)
        if self.headers is not None:
            for key, val in self.headers.items():
                msg += str(key) + str(val) + '\r\n'
        msg += '\r\n' + str(self.body) + '\r\n'
        return msg

    def init(self):
        self.rqst_line = self.rqst_type.upper() + ' '\
                         + self.path + ' ' + HTTP_VERSION + '\r\n'
        self.build_body()
        self.build_headers()

    def build_body(self):
        if self.data_type == DATA['FILE']:
            self.get_file_data()
        elif self.data_type == DATA['INLINE']:
            self.body = self.data

    def build_headers(self):
        # Get parser headers
        if self.headers is not None:
            for header in self.headers:
                self.headers[(header[0] + ': ')] = header[1]

        else:
            # Build default headers
            self.headers = dict()
            self.headers['Accept: '] = '*/*'
            self.headers['Connection: '] = 'close'
            self.headers['Host: '] = str(self.host)

            # Build necessary POST headers if not present
            if self.rqst_type == CMD['POST']:
                self.headers['Content-Type: '] = 'text/plain' if (self.data is None)\
                    else 'application/json'
                # Set the content length to the length of the data
                self.headers['Content-Length: '] = str(len(self.body))

    def get_file_data(self):
        if self.data[-4:] == '.json':
            import json
            with open(self.data, 'r') as file:
                self.body = json.dumps(json.load(file))
        else:
            with open(self.data, 'r') as file:
                self.body = file.read()


class HTTPClient:
    def __init__(self,
                 rqst_type,
                 verbose=False,
                 output='',
                 headers=None,
                 data_inline=None,
                 data_file=None,
                 url='',
                 timeout=None):
        self.rqst_type = rqst_type
        self.verbose = verbose
        self.output = output
        self.headers = headers
        self.data_inline = data_inline
        self.data_file = data_file
        self.body = None
        self.url = url
        self.server_name = None
        self.server_addr = None
        self.server_port = 8080
        self.server = tuple()
        self.router = tuple()
        self.socket = None
        self.timeout = SOCK_TIMEOUT if timeout is None else timeout
        self.window_send = list()
        self.window_recv = list()

        # Turn off logging if verbosity is set to False
        if not self.verbose:
            logging.disable(logging.DEBUG)

        # Initialize client
        self.init()

    @staticmethod
    def debug(message, divider=False):
        if divider:
            logging.debug(message + '\r\n' + DIVIDER)
        else:
            logging.debug(message)

    def init(self):
        # Determine whether the given host address is in IP or URL format
        valid = True
        ip = re.match(REGEX['IP_PORT'], self.url)

        if ip is not None:
            self.server_addr = ip.group('host')
            HTTPClient.debug('Server IP address resolved to: ' + str(self.server_addr))
            self.server_port = int(ip.group('port'))
            HTTPClient.debug('Server port number: ' + str(self.server_port))
            self.server = (self.server_addr, self.server_port)

        else:
            url = re.match(REGEX['URL_PORT'], self.url)
            if url is not None:
                self.server_name = url.group('host')

                # Check if it is localhost
                if self.server_name == 'localhost':
                    pass

                # Otherwise we parse the given URL
                else:
                    host_name = url.group('host')
                    try:
                        host_ip = socket.gethostbyname(host_name)
                        HTTPClient.debug('Server IP address resolved to: ' + host_ip)
                        host_port = 8080
                        if url.group('port') is not None:
                            host_port = url.group('port')
                        HTTPClient.debug('Server port number: ' + str(host_port))
                        self.server_addr = host_ip
                        self.server_port = host_port
                        self.server = (self.server_addr, str(self.server_port))
                    except socket.gaierror:
                        HTTPClient.debug('Could not resolve host name: ' + host_name)

            else:
                HTTPClient.debug('Invalid address format: ' + str(self.server_addr))
                valid = False

        if valid:
            self.router = (self.server_addr, 3000)

            self.run()

    def run(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            syn = self.send_syn()
            synack = self.recv_synack(syn)
            if synack is not None:
                time.sleep(0.5)
                self.send_handshake_ack(synack)

                rqst = self.build_rqst()
                pkts = self.make_pkts(rqst)
                self.send_data(pkts)
                pkts = self.recv_data()

                buffer = ''
                if pkts is not None:
                    buffer = ''
                    pkts.sort(key=lambda p: p.seq_num)
                    for pkt in pkts:
                        if pkt.data != '/ END OF TRANSMISSION /':
                            buffer += pkt.data
                HTTPClient.debug('Data received:\r\n\r\n' + buffer + '\r\n\r\n')

        except KeyboardInterrupt:
            HTTPClient.debug('Client shutting down...')

    def send_syn(self):
        syn = random.randint(0, 100)
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['SYN'],
                               seq_num=syn,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='')
        HTTPClient.debug('Sending SYN packet #' + str(pkt.seq_num))
        self.socket.sendto(pkt.to_bytes(), self.router)

        return syn

    def recv_synack(self, syn):
        syn_ = syn
        self.socket.settimeout(SOCK_TIMEOUT)

        while True:
            try:
                raw, origin = self.socket.recvfrom(BUFFER_SIZE)
                pkt = packet.UDPPacket.from_bytes(raw)
                ack = int(pkt.data)
                if pkt.pkt_type == packet.PKT_TYPE['SYN-ACK'] and ack == syn_:
                    HTTPClient.debug('Received SYN-ACK packet #' + str(pkt.seq_num))
                    return pkt.seq_num

            except socket.timeout:
                HTTPClient.debug('Timed out; will resend SYN packet')
                syn_ = self.send_syn()
                self.socket.settimeout(SOCK_TIMEOUT + 1)

    def send_handshake_ack(self, synack):
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                               seq_num=synack,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='')
        HTTPClient.debug('Sending handshake ACK packet #' + str(pkt.seq_num))
        self.socket.sendto(pkt.to_bytes(), self.router)

    def make_pkts(self, rqst):
        pkts = list()
        seq_num = 0
        buffer = ''
        left_to_send = str(rqst)
        num_pkts = math.ceil(len(left_to_send) / (packet.PKT_MAX - packet.PKT_MIN))
        HTTPClient.debug('Preparing ' + str(num_pkts + 1) + ' packet(s) to send')

        while len(left_to_send) > 0:
            for char in left_to_send:
                if len(buffer) < (packet.PKT_MAX - packet.PKT_MIN):
                    buffer += char

            pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                                   seq_num=seq_num,
                                   peer_ip=self.server_addr,
                                   peer_port=self.server_port,
                                   data=buffer)
            pkts.append(pkt)
            seq_num += 1
            left_to_send = left_to_send[len(buffer):]
            buffer = ''

        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                               seq_num=seq_num,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='/ END OF TRANSMISSION /')
        pkts.append(pkt)

        return pkts

    def send_data(self, pkts):
        last_pkt = pkts[-1]

        while len(pkts) > 0:
            window_ready = False

            while not window_ready:
                pkt = pkts.pop(0)
                self.window_send.append(pkt)
                if len(pkts) == 0 or len(self.window_send) == WINDOW_SIZE:
                    window_ready = True

            for pkt in self.window_send:
                HTTPClient.debug('Sending DATA packet #' + str(pkt.seq_num))
                self.socket.sendto(pkt.to_bytes(), self.router)
                time.sleep(0.1)
            HTTPClient.debug('Window sent, waiting for ACK packets')
            received = False

            while not received:
                acks = self.recv_acks(last_pkt)
                ack_nums = set(ack.seq_num for ack in acks)\
                    if acks is not None else set()
                pkt_nums = set(pkt.seq_num for pkt in self.window_send)\
                    if len(self.window_send) > 0 else set()
                matches = ack_nums & pkt_nums
                resend = list()
                if matches is None:
                    resend = self.window_send
                elif matches == pkt_nums:
                    received = True
                    HTTPClient.debug('Sending window received, sliding down')
                    self.window_send.clear()
                else:
                    resend = [pkt for pkt in self.window_send if pkt.seq_num not in matches]

                if len(resend) > 0:
                    for pkt in resend:
                        HTTPClient.debug('Resending DATA packet #' + str(pkt.seq_num))
                        self.socket.sendto(pkt.to_bytes(), self.router)
                        time.sleep(0.1)
                    resend.clear()

    def recv_acks(self, last_pkt):
        acks = list()
        pkt_nums = set(pkt.seq_num for pkt in self.window_send)
        self.socket.settimeout(SOCK_TIMEOUT)

        try:
            while len(acks) < WINDOW_SIZE:
                raw, origin = self.socket.recvfrom(BUFFER_SIZE)
                ack = packet.UDPPacket.from_bytes(raw)
                if ack.pkt_type == packet.PKT_TYPE['ACK']:
                    HTTPClient.debug('Received ACK packet #' + str(ack.seq_num))
                    acks.append(ack)

                    ack_nums = set(ack.seq_num for ack in acks)
                    matches = ack_nums & pkt_nums
                    if matches == pkt_nums:
                        return acks

                elif ack.pkt_type == packet.PKT_TYPE['SYN-ACK']:
                    HTTPClient.debug('Received SYN-ACK packet #' + str(ack.seq_num)
                                     + '; resending handshake packet')
                    self.send_handshake_ack(ack.seq_num)

                elif ack.pkt_type == packet.PKT_TYPE['NAK']:
                    if max(pkt.seq_num for pkt in self.window_send) < ack.seq_num\
                            < last_pkt.seq_num:
                        HTTPClient.debug('Received NAK packet #' + str(ack.seq_num) + '; will slide down window')
                        acks = list()
                        for pkt in self.window_send:
                            acks.append(packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                                                         seq_num=pkt.seq_num,
                                                         peer_ip=ack.peer_ip,
                                                         peer_port=ack.peer_port,
                                                         data=''))
                    else:
                        HTTPClient.debug('Received NAK packet #' + str(ack.seq_num) + '; will resend missing packet')

        except socket.timeout:
            HTTPClient.debug('Timed out; will resend packets not acknowledged by peer')
            return acks

    def recv_data(self):
        pkts = list()
        seq_nums = {0, 1, 2, 3}
        received = False

        while not received:
            try:
                self.socket.settimeout(SOCK_TIMEOUT)
                raw, origin = self.socket.recvfrom(BUFFER_SIZE)
                pkt = packet.UDPPacket.from_bytes(raw)
                if pkt.pkt_type == packet.PKT_TYPE['DATA']:
                    HTTPClient.debug('Received DATA packet #' + str(pkt.seq_num))

                    if pkt.seq_num in seq_nums\
                            and pkt.seq_num not in [rcv.seq_num for rcv in self.window_recv]:
                        pkts.append(pkt)
                        if len(self.window_recv) < WINDOW_SIZE:
                            self.window_recv.append(pkt)

                    if len(self.window_recv) == WINDOW_SIZE:
                        HTTPClient.debug('Receiving window full, sliding down')
                        for pkt_rcvd in self.window_recv:
                            self.send_ack(pkt_rcvd.seq_num)
                        seq_nums = set(seq_num + WINDOW_SIZE for seq_num in seq_nums)
                        self.window_recv.clear()

                    if pkt.data == '/ END OF TRANSMISSION /':
                        HTTPClient.debug('Received end of transmission #' + str(pkt.seq_num))
                        seq_nums = set(seq_num for seq_num in seq_nums if seq_num <= pkt.seq_num)
                        rcv_nums = set(rcv.seq_num for rcv in pkts)
                        all_nums = set(range(pkt.seq_num))
                        matches = all_nums - rcv_nums
                        if len(matches) == 0:
                            for pkt_rcvd in self.window_recv:
                                self.send_ack(pkt_rcvd.seq_num)
                            self.window_recv.clear()
                            received = True

            except socket.timeout:
                time.sleep(0.1)
                HTTPClient.debug('Timed out; will send NAK packets for missing frames')
                pkt_nums = set(pkt.seq_num for pkt in self.window_recv)
                nak_nums = seq_nums - pkt_nums
                for nak_num in nak_nums:
                    self.send_nak(nak_num)

        return pkts

    def send_ack(self, seq_num):
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                               seq_num=seq_num,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='')
        HTTPClient.debug('Sending ACK packet #' + str(pkt.seq_num))
        self.socket.sendto(pkt.to_bytes(), self.router)

    def send_nak(self, seq_num):
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['NAK'],
                               seq_num=seq_num,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='')
        HTTPClient.debug('Sending NAK packet #' + str(pkt.seq_num))
        self.socket.sendto(pkt.to_bytes(), self.router)

    def build_rqst(self):
        rqst = None

        data_type = ''
        data = ''
        if self.data_file is not None:
            data_type = DATA['FILE']
            data = self.data_file
        elif self.data_inline is not None:
            data_type = DATA['INLINE']
            data = self.data_inline

        url = re.search(REGEX['PATH_ARGS'], self.url).groupdict()
        if url is None:
            HTTPClient.debug('Could not resolve path in URL: ' + self.url)

        else:
            # Generate request
            path_args = url['path']
            if url['args'] is not None:
                path_args += '?' + url['args']

            if self.server_name is not None:
                rqst = Request(rqst_type=self.rqst_type,
                               host=self.server_name,
                               path=path_args,
                               headers=self.headers,
                               data_type=data_type,
                               data=data)
            else:
                rqst = Request(rqst_type=self.rqst_type,
                               host=self.server_addr,
                               path=path_args,
                               headers=self.headers,
                               data_type=data_type,
                               data=data)

        return rqst

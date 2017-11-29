import logging
import math
import packet
import re
import socket
import time

BUFFER_SIZE = 1024
DATA_TIMEOUT = 1
DIVIDER = '-' * 80
ENCODING = 'utf-8'
HTTP_VERSION = 'HTTP/1.1'
ROUTER_PORT = 3000

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
        msg += str(self.body) + '\r\n'
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
        import json
        with open(self.data, 'r') as file:
            self.body = json.dumps(json.load(file))


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
        self.server_port = 80
        self.server = None
        self.socket = None
        self.timeout = 5 if timeout is None else timeout
        self.router = tuple()
        self.connected = False
        self.curr_send = 0
        self.curr_recv = 0
        self.window_send = list()
        self.window_recv = list()
        self.t_start = 0
        self.t_end = 0

        # Initialize client
        self.init()

    @staticmethod
    def debug(message, divider=False):
        if divider:
            logging.debug(message + '\r\n' + DIVIDER)
        else:
            logging.debug(message)

    def last_inorder(self):
        # Return last in-order packet successfully received
        largest = 0
        for pkt in self.window_recv:
            if self.curr_recv > pkt.seq_num > largest:
                largest = pkt.seq_num

        return self.pkt_recv(largest)

    def pkt_recv(self, num):
        # Find a packet with the given sequence number in the receiving window
        for pkt in self.window_recv:
            if pkt.seq_num == num:
                return pkt

        return None

    def pkt_send(self, num):
        # Find a packet with the given sequence number in the sending window
        for pkt in self.window_send:
            if pkt.seq_num == num:
                return pkt

        return None

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
                    # Try to resolve the host name
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

    def send_syn(self):
        # Initialize socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Generate SYN packet
        self.curr_send = packet.PKT_MIN
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['SYN'],
                               seq_num=self.curr_send,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data='')
        HTTPClient.debug('Built packet:\r\n\r\n' + str(pkt), True)

        # Send packet and update sequence numbers
        self.curr_recv += 2 * packet.PKT_MIN
        self.curr_send += 2 * packet.PKT_MIN
        self.socket.sendto(pkt.to_bytes(), self.router)
        HTTPClient.debug('Packet sent to router at: ' + str(self.router[0])
                         + ':' + str(self.router[1])
                         + ' (size = ' + str(len(pkt.data)) + ')')

    def send_ack(self, last=None):
        # Generate ACK packet
        if last is not None:
            pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                                   seq_num=last.seq_num,
                                   peer_ip=self.server_addr,
                                   peer_port=self.server_port,
                                   data='')
        else:
            pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                                   seq_num=3*packet.PKT_MIN,
                                   peer_ip=self.server_addr,
                                   peer_port=self.server_port,
                                   data='')
        HTTPClient.debug('Built packet:\r\n\r\n' + str(pkt), True)

        # Send packet
        self.socket.sendto(pkt.to_bytes(), self.router)
        HTTPClient.debug('Packet sent to router at: ' + str(self.router[0])
                         + ':' + str(self.router[1])
                         + ' (size = ' + str(len(pkt.data)) + ')')

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

    def send_rqst(self, rqst):
        buffer = ''
        left_to_send = str(rqst)

        # Determine how many packets need to be sent
        num_pkts = math.ceil(len(left_to_send) / (packet.PKT_MAX - packet.PKT_MIN))
        HTTPClient.debug('Sending ' + str(num_pkts) + ' packet(s)')

        while len(left_to_send) > 0:
            # Use a buffer to split the request into as many packets as needed
            for char in left_to_send:
                if len(buffer) < (packet.PKT_MAX - packet.PKT_MIN):
                    buffer += char

            pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                                   seq_num=self.curr_send,
                                   peer_ip=self.server_addr,
                                   peer_port=self.server_port,
                                   data=buffer)

            self.curr_send += packet.PKT_MIN + len(buffer)
            self.curr_recv = self.curr_send
            self.window_send.append(pkt)
            HTTPClient.debug('Built packet:\r\n\r\n' + str(pkt), True)

            # Build next packet
            left_to_send = left_to_send[len(buffer):]
            buffer = ''

        # Send window to server
        for pkt in self.window_send:
            self.send_rqst_pkt(pkt)

    def send_rqst_pkt(self, pkt):
        self.socket.sendto(pkt.to_bytes(), self.router)
        HTTPClient.debug('Packet sent to router at: ' + str(self.router[0])
                         + ':' + str(self.router[1])
                         + ' (size = ' + str(len(pkt.data)) + ')')

    def recv(self):
        # Wait for a reply from the server
        self.socket.settimeout(self.timeout)
        raw, origin = self.socket.recvfrom(BUFFER_SIZE)

        # Packet reception
        if raw is not None:
            self.recv_pkt(raw)

    def recv_pkt(self, raw):
        # Extract packet information
        pkt = packet.UDPPacket.from_bytes(raw=raw)
        self.window_recv.append(pkt)
        HTTPClient.debug('Received packet:\r\n\r\n' + str(pkt), True)

        if self.output is not None:
            with open(self.output, 'a') as file:
                file.write(pkt.data)

        # Extract packet information
        pkt_type = pkt.pkt_type
        seq_num = pkt.seq_num
        data = pkt.data

        # Check packet sequence number
        if seq_num == self.curr_recv:

            # Handle SYN-ACK packet
            if pkt_type == packet.PKT_TYPE['SYN-ACK']:
                HTTPClient.debug('Handshake accepted')

                # Add received packet to receiving window
                if pkt not in self.window_recv:
                    self.window_recv.append(pkt)
                self.connected = True

            # Handle DATA packet
            elif pkt_type == packet.PKT_TYPE['DATA']:
                self.curr_recv += packet.PKT_MIN + len(data)
                # Add received packet to receiving window
                if pkt not in self.window_recv:
                    self.window_recv.append(pkt)

                    # Start a timer before sending ACK indicating proper reception
                    self.t_start = time.time()

                # Remove SYN-ACK packet from receiving window
                self.window_recv.remove(self.pkt_recv(2 * packet.PKT_MIN))

                # Older packets can be safely removed from sending window
                for pkt_send in self.window_send:
                    if pkt_send.seq_num < seq_num:
                        self.window_send.remove(pkt_send)

            # Send ACK of last successfully received, in-order packet
            else:
                HTTPClient.debug('Unexpected sequence number (expected '
                                 + str(self.curr_recv)
                                 + ")")
                last = self.last_inorder()
                if last is not None:
                    self.send_ack(last)

        else:
            # If ACK packet, send all potentially misreceived packets again
            if pkt_type == packet.PKT_TYPE['ACK']:
                HTTPClient.debug('Received cumulative ACK packet')

                # Resolve missing handshake ACK packet
                if seq_num == packet.PKT_MIN:
                    HTTPClient.debug('Resending handshake ACK packet')
                    self.send_ack()

                # Resend missing DATA packets
                for pkt_send in self.window_send:
                    if pkt_send.seq_num >= seq_num:
                        HTTPClient.debug('Resending packet #' + str(pkt_send.seq_num))
                        self.send_rqst_pkt(pkt_send)
                    else:
                        # Older packets can be safely removed from sending window
                        self.window_send.remove(pkt_send)

            # Address NAK packet
            elif pkt_type == packet.PKT_TYPE['NAK']:
                HTTPClient.debug('Received NAK packet')
                self.send_rqst_pkt(self.pkt_send(seq_num))

                # Older packets can be safely removed from sending window
                for pkt_send in self.window_send:
                    if pkt_send.seq_num < seq_num:
                        self.window_send.remove(pkt_send)

            # Otherwise, send ACK of last successfully received, in-order packet
            else:
                HTTPClient.debug('Unexpected sequence number (expected '
                                 + str(self.curr_recv)
                                 + ")")
                last = self.last_inorder()
                if last is not None:
                    self.send_ack(last)

    def run(self):
        # Build request
        rqst = self.build_rqst()

        try:
            try:
                # Try establishing a connection
                self.send_syn()

                # Wait for a SYN-ACK packet
                self.recv()

            # Handle timeout
            except socket.timeout:
                HTTPClient.debug('Handshake timed out')

                if self.socket is not None:
                    # Close connection
                    HTTPClient.debug('Closing socket')
                    self.socket.close()

            if self.connected:
                try:
                    # First send an ACK to complete 3-way handshake
                    self.send_ack()
                    self.curr_send += packet.PKT_MIN

                    # Send request and wait for a response
                    self.send_rqst(rqst)

                    while True:
                        # Receive server packet(s)
                        self.recv()

                # Handle timeout by asking for packets again
                except socket.timeout:
                    last = self.last_inorder()
                    if last is not None:
                        self.send_ack(last)
                        HTTPClient.debug('Connection timed out; requesting packets from #'
                                         + str(last.seq_num))

                        try:
                            while True:
                                # Receive server packet(s)
                                self.recv()
                                self.t_end = time.time()

                                # If timer runs out, send ACK indicating good reception
                                if self.t_end - self.t_start > DATA_TIMEOUT:
                                    last = self.last_inorder()
                                    if last is not None\
                                        and last.pkt_type == packet.PKT_TYPE['DATA']:
                                        self.send_ack(last)
                                        HTTPClient.debug('Sending ACK packet indicating reception (#'
                                                         + str(last.seq_num) + ')')

                        # After second timeout, assume server will not respond anymore
                        except socket.timeout:
                            HTTPClient.debug('Connection timed out; assume end of communication')

                    else:
                        HTTPClient.debug('Connection timed out; assume end of communication')

                finally:
                    if self.socket is not None:
                        # Close connection
                        HTTPClient.debug('Closing socket')
                        self.socket.close()

        # Following a keyboard interrupt, stop accepting new connections and exit
        except KeyboardInterrupt:
            HTTPClient.debug('Client shutting down...')

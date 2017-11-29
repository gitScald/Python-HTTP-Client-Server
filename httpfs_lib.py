import json
import logging
import math
import os
import os.path
import packet
import random
import re
import socket
import stat
import _thread
import threading
import time

logging.basicConfig(level=logging.DEBUG,
                    format='(%(asctime)-23s) (%(threadName)-12s) %(message)s')

BUFFER_SIZE = 1024
DIVIDER = '-' * 80
ENCODING = 'utf-8'
HTTP_VERSION = 'HTTP/1.1'
SOCK_TIMEOUT = 2
THREAD_DELAY = 3
WINDOW_SIZE = 4

CMD = {'GET': 'GET',
       'POST': 'POST'}

# List of supported file extensions for Content-Type
EXTENSIONS = ['html', 'json', 'txt', 'xml']

# List of protected files in working directory
FILES = {'BAD_HTTP': 'public/bad_http.html',
         'FORBIDDEN': 'public/forbidden.html',
         'GET': 'public/get.html',
         'NOT_FOUND': 'public/not_found.html',
         'NOT_ALLOWED': 'public/not_allowed.html',
         'STOP': 'public/stop.html'}

# List of supported media types for Content-Type
MEDIA_TYPES = {'html': 'text/html',
               'json': 'application/json',
               'txt': 'text/plain',
               'xml': 'application/xml'}

# List of currently supported status codes
STATUS_CODES = {'OK': '200 OK',
                'CREATED': '201 Created',
                'BAD_REQ': '400 Bad Request',
                'FORBIDDEN': '403 Forbidden',
                'NOT_FOUND': '404 Not Found',
                'NOT_ALLOWED': '405 Method Not Allowed',
                'BAD_HTML': '505 HTTP Version Not Supported'}


class FileServer:
    def __init__(self, args):
        # self.active = True
        self.cwd = os.getcwd()
        self.delay = THREAD_DELAY if args.w else 0
        self.host = '0.0.0.0'
        self.router = tuple()
        self.locks_read = dict()
        self.locks_write = dict()
        self.port = args.p
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clients = list()
        self.threads = dict()
        self.timeout = SOCK_TIMEOUT
        self.wdir = os.path.join(self.cwd, args.d) if args.d is not None else self.cwd

        # Turn off logging if verbosity is set to False
        if not args.v:
            logging.disable(logging.DEBUG)

        self.init()

    @staticmethod
    def debug(message, divider=False):
        if divider:
            logging.debug(message + '\r\n' + DIVIDER)
        else:
            logging.debug(message)

    def init(self):
        FileServer.debug('Starting server...')
        FileServer.debug('Working directory: ' + self.wdir)

        self.host = socket.gethostbyname(socket.gethostname())
        self.router = (self.host, 3000)
        FileServer.debug('Host name: ' + self.host + ':' + str(self.port))

        self.sock.bind((self.host, self.port))
        FileServer.debug('Server awaiting packets...')

        # Provide minimal output if logging is disabled
        if not logging.getLogger().isEnabledFor(logging.DEBUG):
            print('Server name: ', self.host, ':', str(self.port))
            print('Working directory: ', self.wdir)
        self.run()

    def run(self):
        # while self.active:
        try:
            # self.sock.settimeout(0.1)
            raw, origin = self.sock.recvfrom(BUFFER_SIZE)
            pkt = packet.UDPPacket.from_bytes(raw=raw)
            peer = (pkt.peer_ip, pkt.peer_port)

            if pkt.pkt_type == packet.PKT_TYPE['SYN']\
                    and peer not in self.clients:
                name = 'Connection-' + str(len(self.threads))
                t = threading.Thread(name=name,
                                     target=self.handle,
                                     args=(pkt,))
                self.threads[t] = {'CLIENT': tuple(),
                                   'WNDW_RECV': list(),
                                   'WNDW_SEND': list()}
                t.start()
                FileServer.debug('Active connections: ' + str(len(self.threads)))

        except socket.timeout:
            pass

        except KeyboardInterrupt:
            FileServer.debug('Server shutting down...')
            # self.active = False

        self.exit()

    def handle(self, syn_pkt):
        FileServer.debug('Received SYN packet #' + str(syn_pkt.seq_num))
        time.sleep(0.5)
        synack = self.send_synack(syn_pkt)
        client = self.recv_handshake_ack(synack, syn_pkt)

        if client is not None:
            peer = (syn_pkt.peer_ip, syn_pkt.peer_port)
            self.clients.append(peer)
            pkts = self.recv_data(client)

            buffer = ''
            if pkts is not None:
                buffer = ''
                pkts.sort(key=lambda p: p.seq_num)
                for pkt in pkts:
                    if pkt.data != '/ END OF TRANSMISSION /':
                        buffer += pkt.data
            FileServer.debug('Data received:\r\n\r\n' + buffer + '\r\n\r\n')

            resp = self.parse(buffer)
            pkts = self.make_pkts(client, resp)
            self.send_data(pkts)
            self.clients.remove(client)

    def send_synack(self, syn_pkt):
        synack = random.randint(0, 100)
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['SYN-ACK'],
                               seq_num=synack,
                               peer_ip=syn_pkt.peer_ip,
                               peer_port=syn_pkt.peer_port,
                               data=str(syn_pkt.seq_num))
        FileServer.debug('Sending SYN-ACK packet #' + str(pkt.seq_num))
        self.sock.sendto(pkt.to_bytes(), self.router)

        return synack

    def recv_handshake_ack(self, synack, syn_pkt):
        synack_ = synack
        self.sock.settimeout(SOCK_TIMEOUT)

        while True:
            try:
                raw, origin = self.sock.recvfrom(BUFFER_SIZE)
                pkt = packet.UDPPacket.from_bytes(raw)
                if pkt.pkt_type == packet.PKT_TYPE['ACK'] and int(pkt.seq_num) == synack_:
                    FileServer.debug('Received handshake ACK packet #' + str(pkt.seq_num))
                    self.threads[threading.current_thread()]['CLIENT'] = (pkt.peer_ip, pkt.peer_port)
                    return self.threads[threading.current_thread()]['CLIENT']

                elif pkt.pkt_type == packet.PKT_TYPE['DATA']:
                    FileServer.debug('Received DATA packet; requesting another handshake packet')
                    synack_ = self.send_synack(syn_pkt)
                    self.sock.settimeout(SOCK_TIMEOUT + 1)

            except socket.timeout:
                FileServer.debug('Timed out; will resend SYN-ACK packet')
                synack_ = self.send_synack(syn_pkt)
                self.sock.settimeout(SOCK_TIMEOUT + 1)

    def recv_data(self, client):
        pkts = list()
        seq_nums = {0, 1, 2, 3}
        received = False

        while not received:
            try:
                self.sock.settimeout(SOCK_TIMEOUT)
                raw, origin = self.sock.recvfrom(BUFFER_SIZE)
                pkt = packet.UDPPacket.from_bytes(raw)
                if pkt.pkt_type == packet.PKT_TYPE['DATA']:
                    FileServer.debug('Received DATA packet #' + str(pkt.seq_num))

                    if pkt.seq_num in seq_nums\
                            and pkt.seq_num not in [rcv.seq_num for rcv in self.threads[threading.current_thread()]['WNDW_RECV']]:
                        pkts.append(pkt)
                        if len(self.threads[threading.current_thread()]['WNDW_RECV']) < WINDOW_SIZE:
                            self.threads[threading.current_thread()]['WNDW_RECV'].append(pkt)

                    if len(self.threads[threading.current_thread()]['WNDW_RECV']) == WINDOW_SIZE:
                        FileServer.debug('Receiving window full, sliding down')
                        for pkt_rcvd in self.threads[threading.current_thread()]['WNDW_RECV']:
                            self.send_ack(pkt_rcvd.seq_num, client)
                        seq_nums = set(seq_num + WINDOW_SIZE for seq_num in seq_nums)
                        self.threads[threading.current_thread()]['WNDW_RECV'].clear()

                    if pkt.data == '/ END OF TRANSMISSION /':
                        FileServer.debug('Received end of transmission #' + str(pkt.seq_num))
                        seq_nums = set(seq_num for seq_num in seq_nums if seq_num <= pkt.seq_num)
                        rcv_nums = set(rcv.seq_num for rcv in pkts)
                        all_nums = set(range(pkt.seq_num))
                        matches = all_nums - rcv_nums
                        if len(matches) == 0:
                            for pkt_rcvd in self.threads[threading.current_thread()]['WNDW_RECV']:
                                self.send_ack(pkt_rcvd.seq_num, client)
                            self.threads[threading.current_thread()]['WNDW_RECV'].clear()
                            received = True

            except socket.timeout:
                time.sleep(0.1)
                FileServer.debug('Timed out; will send NAK packets for missing frames')
                pkt_nums = set(pkt.seq_num for pkt in self.threads[threading.current_thread()]['WNDW_RECV'])
                nak_nums = seq_nums - pkt_nums
                for nak_num in nak_nums:
                    self.send_nak(nak_num, client)

        return pkts

    def send_ack(self, seq_num, client):
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                               seq_num=seq_num,
                               peer_ip=client[0],
                               peer_port=client[1],
                               data='')
        FileServer.debug('Sending ACK packet #' + str(pkt.seq_num))
        self.sock.sendto(pkt.to_bytes(), self.router)

    def send_nak(self, seq_num, client):
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['NAK'],
                               seq_num=seq_num,
                               peer_ip=client[0],
                               peer_port=client[1],
                               data='')
        FileServer.debug('Sending NAK packet #' + str(pkt.seq_num))
        self.sock.sendto(pkt.to_bytes(), self.router)

    @staticmethod
    def make_pkts(client, resp):
        pkts = list()
        seq_num = 0
        buffer = ''
        left_to_send = Response.to_str(resp)
        num_pkts = math.ceil(len(left_to_send) / (packet.PKT_MAX - packet.PKT_MIN))
        FileServer.debug('Preparing ' + str(num_pkts + 1) + ' packet(s) to send')

        while len(left_to_send) > 0:
            for char in left_to_send:
                if len(buffer) < (packet.PKT_MAX - packet.PKT_MIN):
                    buffer += char

            pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                                   seq_num=seq_num,
                                   peer_ip=client[0],
                                   peer_port=client[1],
                                   data=buffer)
            pkts.append(pkt)
            seq_num += 1
            left_to_send = left_to_send[len(buffer):]
            buffer = ''

        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                               seq_num=seq_num,
                               peer_ip=client[0],
                               peer_port=client[1],
                               data='/ END OF TRANSMISSION /')
        pkts.append(pkt)

        return pkts

    def send_data(self, pkts):
        last_pkt = pkts[-1]

        while len(pkts) > 0:
            window_ready = False

            while not window_ready:
                pkt = pkts.pop(0)
                self.threads[threading.current_thread()]['WNDW_SEND'].append(pkt)
                if len(pkts) == 0 or len(self.threads[threading.current_thread()]['WNDW_SEND']) == WINDOW_SIZE:
                    window_ready = True

            for pkt in self.threads[threading.current_thread()]['WNDW_SEND']:
                FileServer.debug('Sending DATA packet #' + str(pkt.seq_num))
                self.sock.sendto(pkt.to_bytes(), self.router)
                time.sleep(0.1)
            FileServer.debug('Window sent, waiting for ACK packets')
            received = False

            while not received:
                acks = self.recv_acks(last_pkt)
                ack_nums = set(ack.seq_num for ack in acks)\
                    if acks is not None else set()
                pkt_nums = set(pkt.seq_num for pkt in self.threads[threading.current_thread()]['WNDW_SEND'])\
                    if len(self.threads[threading.current_thread()]['WNDW_SEND']) > 0 else set()
                matches = ack_nums & pkt_nums
                resend = list()
                if matches is None:
                    resend = self.threads[threading.current_thread()]['WNDW_SEND']
                elif matches == pkt_nums:
                    received = True
                    FileServer.debug('Sending window received, sliding down')
                    self.threads[threading.current_thread()]['WNDW_SEND'].clear()
                else:
                    resend = [pkt for pkt in self.threads[threading.current_thread()]['WNDW_SEND'] if pkt.seq_num not in matches]

                if len(resend) > 0:
                    for pkt in resend:
                        FileServer.debug('Resending DATA packet #' + str(pkt.seq_num))
                        self.sock.sendto(pkt.to_bytes(), self.router)
                        time.sleep(0.1)
                    resend.clear()

    def recv_acks(self, last_pkt):
        acks = list()
        pkt_nums = set(pkt.seq_num for pkt in self.threads[threading.current_thread()]['WNDW_SEND'])
        self.sock.settimeout(SOCK_TIMEOUT)

        try:
            while len(acks) < WINDOW_SIZE:
                raw, origin = self.sock.recvfrom(BUFFER_SIZE)
                ack = packet.UDPPacket.from_bytes(raw)
                if ack.pkt_type == packet.PKT_TYPE['ACK']:
                    FileServer.debug('Received ACK packet #' + str(ack.seq_num))
                    acks.append(ack)

                    ack_nums = set(ack.seq_num for ack in acks)
                    matches = ack_nums & pkt_nums
                    if matches == pkt_nums:
                        return acks

                elif ack.pkt_type == packet.PKT_TYPE['NAK']:
                    if max(pkt.seq_num for pkt in self.threads[threading.current_thread()]['WNDW_SEND']) < ack.seq_num\
                            < last_pkt.seq_num:
                        FileServer.debug('Received NAK packet #' + str(ack.seq_num) + '; will slide down window')
                        acks = list()
                        for pkt in self.threads[threading.current_thread()]['WNDW_SEND']:
                            acks.append(packet.UDPPacket(pkt_type=packet.PKT_TYPE['ACK'],
                                                         seq_num=pkt.seq_num,
                                                         peer_ip=ack.peer_ip,
                                                         peer_port=ack.peer_port,
                                                         data=''))
                        return acks

                    else:
                        FileServer.debug('Received NAK packet #' + str(ack.seq_num) + '; will resend missing packet')

        except socket.timeout:
            FileServer.debug('Timed out; will resend packets not acknowledged by peer')
            return acks

    def parse(self, rqst):
        lines = rqst.split('\r\n')

        # Only handle HTTP version 1.1
        if HTTP_VERSION not in lines[0]:
            return self.bad_http()

        path = lines[0].split()[1]
        # Catalog the path as a potential lock
        if path not in self.locks_read:
            self.locks_read[path] = 0
        if path not in self.locks_write:
            self.locks_write[path] = threading.Event()
            self.locks_write[path].set()

        # Disallow requests outside of the 'public' directory
        # Still allows the creation of subdirectories within the 'public' directory
        if (path != '/')\
                and (not path.startswith('/public'))\
                and (os.path.join(self.cwd, 'public') not in self.wdir):

            return self.forbidden()

        elif CMD['GET'] in lines[0]:
            return self.get(rqst=rqst)

        elif CMD['POST'] in lines[0]:
            return self.post(rqst=rqst)

        else:
            return None

    def base_headers(self):
        headers = 'Date: ' + time.asctime(time.localtime()) + '\r\n'
        headers += 'Accept: application/json, text/plain' + '\r\n'
        headers += 'Connection: close' + '\r\n'
        headers += 'Host: ' + self.host + ':' + str(self.port) + '\r\n'
        headers += 'Server: httpfs_lib/1.0' + '\r\n'

        return headers

    def bad_http(self):
        content = ''
        with open(FILES['BAD_HTTP'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['BAD_HTML'], content, headers)

        return resp

    def forbidden(self):
        content = ''
        with open(FILES['FORBIDDEN'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['FORBIDDEN'], content, headers)

        return resp

    def not_allowed(self):
        content = ''
        with open(FILES['NOT_ALLOWED'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['NOT_ALLOWED'], content, headers)

        return resp

    def not_found(self):
        content = ''
        with open(FILES['NOT_FOUND'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['NOT_FOUND'], content, headers)

        return resp

    def stop(self):
        content = ''
        with open(FILES['STOP'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['OK'], content, headers)

        return resp

    @staticmethod
    def args(args):
        formatted = {'args': {}}
        for arg in args:
            split = arg.split('=')
            # If no arguments can be found, return
            if len(split) < 2:
                return
            key = split[0]
            val = split[1]
            formatted['args'][key] = val

        return formatted

    @staticmethod
    def content_disposition(path):
        # Determine Content-Disposition header value
        extension = FileServer.extension(path)
        if extension is not None:
            if extension == 'html':
                # HTML files will be suggested for viewing in a browser
                return 'Content-Disposition: inline'

            else:
                # Grab the fully qualified file name
                dir_index = path.rfind('/') + 1
                return 'Content-Disposition: attachment; filename="' + path[dir_index:] + '\"'

    @staticmethod
    def content_type(path):
        # Determine file extension for Content-Type header
        extension = FileServer.extension(path)
        if extension is not None:
            if extension in EXTENSIONS:
                return 'Content-Type: ' + MEDIA_TYPES[extension]

            # If extension is not supported, assume text/plain
            else:
                return 'Content-Type: ' + MEDIA_TYPES['.txt']

    @staticmethod
    def dir(path):
        files = os.listdir(path)
        formatted = {'dir': [], 'file': []}
        for file in files:
            if os.path.isdir(file):
                formatted['dir'].append(file + '/')
            else:
                formatted['file'].append(file)

        return formatted

    @staticmethod
    def extension(path):
        split = path.split('.')
        if len(split) > 1:
            return split[-1]
        else:
            return None

    def get(self, rqst):
        lines = rqst.split('\r\n')
        path = lines[0].split()[1]

        headers = self.base_headers()
        content = ''

        # If no path is specified, return cwd listing
        if path == '/':
            content += json.dumps(self.dir(self.cwd), sort_keys=True, indent=4)
            headers += 'Content-Type: application/json' + '\r\n'
            resp = Response(STATUS_CODES['OK'], content, headers)

            return resp

        else:
            query_index = path.find('?')
            path_end = query_index if query_index > 0 else len(path)

            if os.path.isfile(path[1:path_end]):
                reading = False
                try:
                    self.locks_write[path].wait()
                    FileServer.debug('No writer threads in file \'' + path + '\'')

                    self.locks_read[path] += 1
                    FileServer.debug('Acquired lock to read file \'' + path + '\'')
                    reading = True

                    if FILES['STOP'] in path:
                        FileServer.debug('Received stop request')
                        self.stop()
                        _thread.interrupt_main()

                    args = re.findall('(\w+=\w+)+', path, re.IGNORECASE)
                    if args is not None:
                        content += json.dumps(self.args(args), sort_keys=True, indent=4)

                    with open(path[1:path_end], 'r') as file:
                        content += file.read() + '\r\n'

                    time.sleep(self.delay)

                finally:
                    if reading:
                        self.locks_read[path] -= 1
                        FileServer.debug('Released lock to read from file \'' + path + '\'')

                # Last modification date
                stats = os.stat(path[1:path_end])
                mtime = time.asctime(time.localtime(stats[stat.ST_MTIME]))
                headers += 'Last-Modified: ' + mtime + '\r\n'
                headers += self.content_type(path) + '\r\n'
                headers += self.content_disposition(path) + '\r\n'
                headers += 'Content-Length: ' + str(len(content)) + '\r\n'
                resp = Response(STATUS_CODES['OK'], content, headers)

                return resp

            # If path is not valid, form not found response
            else:
                return self.not_found()

    def post(self, rqst):
        lines = rqst.split('\r\n')
        path = lines[0].split()[1]
        headers = self.base_headers()

        if any(FILE in path for FILE in FILES.values()):
            return self.not_allowed()

        else:
            body = rqst.split('\r\n\r\n')[1]
            content = ''

            media_type = re.search('Content-Type:\s*application/json', rqst, re.IGNORECASE)
            if media_type is not None:
                try:
                    body_raw = json.loads(body)
                    content = json.dumps(body_raw, sort_keys=True, indent=4)
                    headers += 'Content-Type: application/json' + '\r\n'
                except json.JSONDecodeError:
                    pass

            else:
                args = body.split('&')
                content = json.dumps(self.args(args), sort_keys=True, indent=4)

                if content == 'null':
                    content = body
                    headers += 'Content-Type: text/plain' + '\r\n'
                else:
                    headers += 'Content-Type: application/json' + '\r\n'

            try:
                self.locks_write[path].wait()
                FileServer.debug('No other writer threads in file \'' + path + '\'')

                while self.locks_read[path] > 0:
                    FileServer.debug('Reader thread(s) holding the lock to file \''
                                     + path + '\'')

                self.locks_write[path].clear()
                FileServer.debug('Acquired lock to write to file \'' + path + '\'')

                created = False
                path_full = self.wdir + path
                if not os.path.isfile(path_full):
                    os.makedirs(os.path.dirname(path_full), exist_ok=True)
                    created = True
                with open(path_full, 'w') as file:
                    file.write(content)
                time.sleep(self.delay)

            finally:
                if not self.locks_write[path].is_set():
                    self.locks_write[path].set()
                    FileServer.debug('Released lock to write to file \'' + path + '\'')

            if created:
                resp = Response(STATUS_CODES['CREATED'], content, headers)
                return resp

            else:
                resp = Response(STATUS_CODES['OK'], content, headers)
                return resp

    def exit(self):
        try:
            for t in self.threads:
                t.join()
                self.threads.pop(t)
        except RuntimeError:
            pass

        self.sock.close()
        FileServer.debug('Server shut down successfully.')


class Response:
    def __init__(self, code, content='', headers=''):
        self.code = HTTP_VERSION + ' ' + code + '\r\n'
        self.content = content
        self.headers = headers

    def to_str(self):
        return self.code + self.headers + '\r\n' + self.content

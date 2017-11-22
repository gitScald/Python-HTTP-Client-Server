import json
import logging
import os
import os.path
import packet
import re
import socket
import stat
import _thread
import threading
import time

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-12s) %(message)s')

BUFFER_SIZE = 1024
DIVIDER = '-' * 80
ENCODING = 'utf-8'
HTTP_VERSION = 'HTTP/1.1'
THREAD_DELAY = 10
WINDOW_SIZE = pow(2, 31)

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
        self.active = True
        self.cwd = os.getcwd()
        self.delay = THREAD_DELAY if args.w else 0
        self.host = ''
        self.locks_read = {}
        self.locks_write = {}
        self.port = args.p
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.threads = []
        self.seq_nums = {}
        self.timeout = 1
        self.wdir = os.path.join(self.cwd, args.d) if args.d is not None else self.cwd
        self.window_send = []
        self.window_recv = []

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
        FileServer.debug('Host name: ' + self.host + ':' + str(self.port))

        self.sock.bind((self.host, self.port))
        FileServer.debug('Server awaiting packets...')

        # Provide minimal output if logging is disabled
        if not logging.getLogger().isEnabledFor(logging.DEBUG):
            print('Server name: ', self.host, ':', str(self.port))
            print('Working directory: ', self.wdir)
        self.run()

    def run(self):
        while self.active:
            try:
                try:
                    self.sock.settimeout(self.timeout)

                    # Receive packet
                    rqst, origin = self.sock.recvfrom(BUFFER_SIZE)
                    if rqst is not None:
                        pkt = packet.UDPPacket.from_bytes(raw=rqst)

                        name = 'RecvThread-' + str(len(self.threads))

                        # Each new connection is handled by a separate thread
                        t = threading.Thread(name=name,
                                             target=self.handle,
                                             args=(pkt, origin))
                        self.threads.append(t)
                        t.start()
                        FileServer.debug('Active connections: ' + str(len(self.threads)))

                # Do nothing on timeout
                except socket.timeout:
                    pass

            # Following a keyboard interrupt, stop accepting new connections and exit
            except KeyboardInterrupt:
                FileServer.debug('Server shutting down...')
                self.active = False

        self.exit()

    def handle(self, pkt, origin):
        try:
            # Print packet contents
            FileServer.debug('Received packet:\r\n\r\n' + str(pkt), True)

            # Extract packet information
            pkt_type = pkt.pkt_type
            seq_num = pkt.seq_num
            peer_ip = pkt.peer_ip
            peer_port = pkt.peer_port
            dest = (peer_ip, peer_port)

            # Acknowledge SYN packet
            if pkt_type == packet.PKT_TYPE['SYN']\
                    and seq_num == 0\
                    and threading.current_thread() not in self.seq_nums:
                FileServer.debug('Received SYN packet')
                # Add an entry into the index of sequence numbers
                self.seq_nums[threading.current_thread()] = seq_num
                self.send_synack(origin, dest)

            # Address ACK packet
            elif pkt_type == packet.PKT_TYPE['ACK']\
                    and seq_num >= 1\
                    and threading.current_thread() not in self.seq_nums:
                FileServer.debug('Received ACK packet')

            # Address NAK packet
            elif pkt_type == packet.PKT_TYPE['NAK']\
                    and seq_num >= 1\
                    and threading.current_thread() not in self.seq_nums:
                FileServer.debug('Received NAK packet')

            # Acknowledge DATA packet and parse client request
            # elif pkt_type == packet.PKT_TYPE['DATA']\
            #         and seq_num >= 1\
            #         and threading.current_thread() not in self.seq_nums:
            elif pkt_type == packet.PKT_TYPE['DATA'] \
                    and threading.current_thread() not in self.seq_nums:
                FileServer.debug('Received DATA packet')
                rqst = pkt.data
                self.parse(origin, dest, rqst)

            # Reject all other cases
            else:
                FileServer.debug('Unexpected packet; packet dropped')

            # Clean up thread
            self.threads.remove(threading.current_thread())
            self.seq_nums.pop(threading.current_thread())

        except Exception as e:
            FileServer.debug(e)

    def send_synack(self, origin, dest):
        # Generate SYN-ACK packet
        self.seq_nums[threading.current_thread()] += 1
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['SYN-ACK'],
                               seq_num=1,
                               peer_ip=dest[0],
                               peer_port=dest[1],
                               data='')
        FileServer.debug('Formed packet:\r\n' + DIVIDER + '\r\n' + str(pkt), True)

        # Send packet
        self.sock.sendto(pkt.to_bytes(), origin)
        FileServer.debug('Packet sent to router at: ' + str(origin[0])
                         + ':' + str(origin[1])
                         + ' (size = ' + str(len(pkt.data)) + ')')

    def parse(self, origin, dest, rqst):
        lines = rqst.split('\r\n')

        # Only handle HTTP version 1.1
        if HTTP_VERSION not in lines[0]:
            FileServer.debug('Handling wrong HTTP request')
            self.bad_http(origin, dest)

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
            FileServer.debug('Handling forbidden request')
            self.forbidden(origin, dest)

        elif CMD['GET'] in lines[0]:
            FileServer.debug('Handling GET request')
            self.get(origin, dest, rqst)

        elif CMD['POST'] in lines[0]:
            FileServer.debug('Handling POST request')
            self.post(origin, dest, rqst)

        else:
            FileServer.debug('Unrecognized request format: ' + rqst[0])

    def base_headers(self):
        headers = 'Date: ' + time.asctime(time.localtime()) + '\r\n'
        headers += 'Accept: application/json, text/plain' + '\r\n'
        headers += 'Connection: close' + '\r\n'
        headers += 'Host: ' + self.host + ':' + str(self.port) + '\r\n'
        headers += 'Server: httpfs_lib/1.0' + '\r\n'

        return headers

    def bad_http(self, origin, dest):
        content = ''
        with open(FILES['BAD_HTTP'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['BAD_HTML'], content, headers)
        self.send_resp(origin, dest, resp)

    def forbidden(self, origin, dest):
        content = ''
        with open(FILES['FORBIDDEN'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['FORBIDDEN'], content, headers)
        self.send_resp(origin, dest, resp)

    def not_allowed(self, origin, dest):
        content = ''
        with open(FILES['NOT_ALLOWED'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['NOT_ALLOWED'], content, headers)
        self.send_resp(origin, dest, resp)

    def not_found(self, origin, dest):
        content = ''
        with open(FILES['NOT_FOUND'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['NOT_FOUND'], content, headers)
        self.send_resp(origin, dest, resp)

    def stop(self, origin, dest):
        content = ''
        with open(FILES['STOP'], 'r') as file:
            content += file.read()
        headers = self.base_headers()
        headers += 'Content-Type: text/html' + '\r\n'
        headers += 'Content-Length: ' + str(len(content)) + '\r\n'
        resp = Response(STATUS_CODES['OK'], content, headers)
        self.send_resp(origin, dest, resp)

        # Interrupt main thread
        _thread.interrupt_main()

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

    def get(self, origin, dest, rqst):
        lines = rqst.split('\r\n')
        path = lines[0].split()[1]

        headers = self.base_headers()
        content = ''

        # If no path is specified, return cwd listing
        if path == '/':
            content += json.dumps(self.dir(self.cwd), sort_keys=True, indent=4)
            headers += 'Content-Type: application/json' + '\r\n'

            # Form request and send
            resp = Response(STATUS_CODES['OK'], content, headers)
            self.send_resp(origin, dest, resp)

        else:
            # Check if a query is part of the request
            query_index = path.find('?')
            path_end = query_index if query_index > 0 else len(path)

            # Verify if path is valid, omitting query
            if os.path.isfile(path[1:path_end]):
                reading = False
                try:
                    # Wait until writing threads are done with the file
                    self.locks_write[path].wait()
                    FileServer.debug('No writer threads in file \'' + path + '\'')

                    # Acquire lock to read the file
                    self.locks_read[path] += 1
                    FileServer.debug('Acquired lock to read file \'' + path + '\'')
                    reading = True

                    # Close server if path points to 'public/stop.html'
                    if FILES['STOP'] in path:
                        FileServer.debug('Received stop request')
                        self.stop(origin, dest)
                        return

                    # Add query arguments to output
                    args = re.findall('(\w+=\w+)+', path, re.IGNORECASE)
                    if args is not None:
                        content += json.dumps(self.args(args), sort_keys=True, indent=4)

                    # Grab file contents
                    with open(path[1:path_end], 'r') as file:
                        content += file.read() + '\r\n'

                    # Optional busy wait delay to test concurrency
                    time.sleep(self.delay)

                finally:
                    # Decrement number of readers
                    if reading:
                        self.locks_read[path] -= 1
                        FileServer.debug('Released lock to read fromm file \'' + path + '\'')

                # Last modification date
                stats = os.stat(path[1:path_end])
                mtime = time.asctime(time.localtime(stats[stat.ST_MTIME]))
                headers += 'Last-Modified: ' + mtime + '\r\n'

                # Determine Content-Type and Content-Disposition headers
                headers += self.content_type(path) + '\r\n'
                headers += self.content_disposition(path) + '\r\n'

                # Form request and send
                headers += 'Content-Length: ' + str(len(content)) + '\r\n'
                resp = Response(STATUS_CODES['OK'], content, headers)
                self.send_resp(origin, dest, resp)

            # If path is not valid, form not found response
            else:
                self.not_found(origin, dest)

    def post(self, origin, dest, rqst):
        lines = rqst.split('\r\n')
        path = lines[0].split()[1]

        headers = self.base_headers()

        # Deny access to already-existing files (except dummy post.html)
        if any(FILE in path for FILE in FILES.values()):
            self.not_allowed(origin, dest)
            return

        else:
            # Grab message body
            body = rqst.split('\r\n\r\n')[1]
            content = ''

            # If Content-Type is JSON, take advantage of pretty formatting
            media_type = re.search('Content-Type:\s*application/json', rqst, re.IGNORECASE)
            if media_type is not None:
                try:
                    body_raw = json.loads(body)
                    content = json.dumps(body_raw, sort_keys=True, indent=4)
                    headers += 'Content-Type: application/json' + '\r\n'
                except json.JSONDecodeError:
                    pass

            # If not, try to put it into nice JSON format
            else:
                args = body.split('&')
                content = json.dumps(self.args(args), sort_keys=True, indent=4)

                # If JSON formatting failed, resort to pure copy-and-paste
                if content == 'null':
                    content = body
                    headers += 'Content-Type: text/plain' + '\r\n'
                else:
                    headers += 'Content-Type: application/json' + '\r\n'

            try:
                # Wait until other writing threads are done with the file
                self.locks_write[path].wait()
                FileServer.debug('No other writer threads in file \'' + path + '\'')

                # Wait until reader threads are done with the file
                while self.locks_read[path] > 0:
                    print('Reader thread(s) holding the lock to file \'' + path + '\'')
                    time.sleep(1)

                # Acquire lock to write to the file
                self.locks_write[path].clear()
                FileServer.debug('Acquired lock to write to file \'' + path + '\'')

                # Write contents to file
                created = False
                # Check if the file already exists
                path_full = self.wdir + path
                if not os.path.isfile(path_full):
                    # Create subdirectories if necessary
                    os.makedirs(os.path.dirname(path_full), exist_ok=True)
                    created = True
                with open(path_full, 'w') as file:
                    file.write(content)

                # Optional busy wait delay to test concurrency
                time.sleep(self.delay)

            finally:
                # Release writer's lock
                if not self.locks_write[path].is_set():
                    self.locks_write[path].set()
                    FileServer.debug('Released lock to write to file \'' + path + '\'')

            # If file had to be created, reply with status 201
            if created:
                # Form request and send
                resp = Response(STATUS_CODES['CREATED'], content, headers)
                self.send_resp(origin, dest, resp)

            # If file already existed, reply with status 200
            else:
                # Form request and send
                resp = Response(STATUS_CODES['OK'], content, headers)
                self.send_resp(origin, dest, resp)

    def send_resp(self, origin, dest, resp):
        # Generate packet
        pkt = packet.UDPPacket(pkt_type=packet.PKT_TYPE['DATA'],
                               seq_num=1,
                               peer_ip=dest[0],
                               peer_port=dest[1],
                               data=Response.to_str(resp))
        FileServer.debug('Formed packet:\r\n' + DIVIDER + '\r\n' + str(pkt), True)

        # Send packet
        self.sock.sendto(pkt.to_bytes(), origin)
        FileServer.debug('Packet sent to router at: ' + str(origin[0])
                         + ':' + str(origin[1])
                         + ' (size = ' + str(len(pkt.data)) + ')')

    def exit(self):
        # Make sure all other threads finish processing their requests
        for t in self.threads:
            t.join()

        self.sock.close()
        FileServer.debug('Server shut down successfully.')


class Response:
    def __init__(self, code, content='', headers=''):
        self.code = HTTP_VERSION + ' ' + code + '\r\n'
        self.content = content
        self.headers = headers

    def to_str(self):
        return self.code + self.headers + '\r\n' + self.content

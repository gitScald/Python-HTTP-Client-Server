import logging
import packet
import re
import socket

BUFFER_SIZE = 1024
DIVIDER = '-' * 80
ENCODING = 'utf-8'
HTTP_VERSION = 'HTTP/1.1'

CMD = {'GET': 'GET',
       'POST': 'POST'}
DATA = {'FILE': '-f',
        'INLINE': '-d'}
REGEX = {'IP_PORT': r'^(?P<host>((http|https):\/{2})?(?P<ip>(\d{1,3}\.){3}\d{1,3}))(:?(?P<port>\d+)?)',
         'PATH_ARGS': r'(?P<path>\/(\w+\/?)*(\.\w+)?)(\?)?(?P<args>\w+=\w+&?)*$',
         'URL_PORT': r'^(?P<host>((http|https):\/{2})?(w{3}\.)?\w+\.\w+)(:?(?P<port>\d+)?)'}

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-12s) %(message)s')


class Request:
    def __init__(self,
                 rqst_type,
                 host=(),
                 path='/',
                 headers={},
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

    def __repr__(self):
        return self.rqst_line + self.headers + self.body

    def init(self):
        self.rqst_line = self.rqst_type + ' ' + self.path + HTTP_VERSION + '\r\n'
        self.build_body(self.body)
        self.build_headers(self.headers)

    def build_body(self, body = None):
        if self.data_type == DATA['FILE']:
            self.get_file_data()
        elif self.data_type == DATA['INLINE']:
            self.body = self.data

    def build_headers(self, headers = None):
        # Get parser headers
        for header in self.headers:
            self.headers[(header[0] + ': ')] = header[1]

        # Build default headers
        if 'Accept:'.strip() not in self.headers:
            self.headers['Accept: '] = '*/*'
        if 'Connection:'.strip() not in self.headers:
            self.headers['Connection: '] = 'keep-alive'
        if 'Host:'.strip() not in self.headers:
            self.headers['Host: '] = self.host[0] + ':' + self.host[1]

        # Build necessary POST headers if not present
        if self.rqst_type == CMD['POST']:
            if 'Content-Type:'.strip() not in self.headers:
                self.headers['Content-Type: '] = 'text/plain' if (self.data is None)\
                    else 'application/json'
            # Set the content length to the length of the data
            if 'Content-Length:'.strip() not in self.headers:
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
                 headers={},
                 data_inline=None,
                 data_file=None,
                 url='',
                 timeout=5):
        self.rqst_type = rqst_type
        self.verbose = verbose
        self.output = output
        self.headers = headers
        self.data_inline = data_inline
        self.data_file = data_file
        self.body = None
        self.url = url
        self.server_addr = 'httpbin.org/get'
        self.server_port = 80
        self.server = None
        self.socket = None
        self.connect = None
        self.timeout = timeout

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
            self.debug('Server IP address resolved to: ' + self.server_addr)
            self.server_port = ip.group('port')
            self.debug('Server port number: ' + self.server_port)

        else:
            # Check if it is localhost
            if self.server_addr == 'localhost':
                pass
            # Otherwise we parse the given URL
            else:
                url = re.match(REGEX['URL_PORT'], self.url)
                if url is not None:
                    # Try to resolve the host name
                    host_name = url.group('host')
                    host_ip = ''
                    try:
                        host_ip = socket.gethostbyname(host_name)
                        self.debug('Server IP address resolved to: ' + host_ip)
                        host_port = 80
                        if url.group('port') is not None:
                            host_port = url.group('port')
                        self.debug('Server port number: ' + str(host_port))
                        self.server_addr = host_ip
                        self.server_port = host_port
                        self.server = (self.server_addr, self.server_port)
                    except socket.gaierror:
                        self.debug('Could not resolve host name: ' + host_name)

                else:
                    self.debug('Invalid address format: ' + self.server_addr)
                    valid = False

        if valid:
            self.run()

    def run(self):
        # Build request
        data_type = ''
        data = ''
        if self.data_file is not None:
            data_type = DATA['FILE']
            data = self.data_file
        elif self.data_inline is not None:
            data_type = DATA['INLINE']
            data = self.data_inline

        r = re.compile(REGEX['PATH_ARGS'])
        # if url is None:
        #     self.debug('Could not resolve path in URL: ' + self.url)

        print([m.groupdict() for m in r.finditer(self.url)])

        # else:
        #     rqst = Request(rqst_type=self.rqst_type,
        #                    host=self.server,
        #                    path=url.group('path'),
        #                    headers=self.headers,
        #                    data_type=data_type,
        #                    data=data)
        #     # pkt = packet.UDPPacket()
        #     self.debug('Built request:' + str(rqst), True)
        #
        #     # Initialize socket and send request
        #     self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #     self.socket.sendto(rqst, self.server)
        #     # self.socket.sendto(pkt, self.server)
        #     self.socket.settimeout(self.timeout)
        #     self.receive()

    def receive(self):
        # Wait for a reply from the server
        resp = self.socket.recvfrom(BUFFER_SIZE)
        if resp is not None:
            self.debug(str(resp))
            if self.output is not None:
                with open(self.output, 'a') as file:
                    file.write(self.output)

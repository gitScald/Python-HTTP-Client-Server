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
            self.headers['Connection: '] = 'keep-alive'
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
        self.server_name = None
        self.server_addr = None
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

    def build_rqst(self):
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
            self.debug('Could not resolve path in URL: ' + self.url)

        else:
            # Generate request
            rqst = None
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
                               host=self.server,
                               path=path_args,
                               headers=self.headers,
                               data_type=data_type,
                               data=data)

        return rqst

    def send_rqst(self, rqst):
        # Initialize socket and send request
        # self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.socket.sendto(rqst, self.server)
        # self.socket.sendto(pkt, self.server)
        # self.socket.settimeout(self.timeout)

        # TCP test
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(self.server)
        self.socket.sendall(str(rqst).encode(ENCODING))
        print(self.socket.recv(BUFFER_SIZE).decode(ENCODING))

    def recv(self):
        # Wait for a reply from the server
        resp = self.socket.recvfrom(BUFFER_SIZE)
        if resp is not None:
            if self.output is not None:
                with open(self.output, 'a') as file:
                    file.write(self.output)

        return resp

    def run(self):
        # Build request
        rqst = self.build_rqst()
        self.debug('Built request:\r\n\r\n' + str(rqst), True)

        self.send_rqst(rqst)
        resp = str(self.recv()).decode(ENCODING)
        self.debug('Received response:\r\n\r\n' + str(resp), True)

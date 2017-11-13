import logging
import packet
import re
import socket

BUFFER_SIZE = 1024
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
                 headers={},
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
        self.router = ()

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
            self.debug('Server IP address resolved to: ' + str(self.server_addr))
            self.server_port = int(ip.group('port'))
            self.debug('Server port number: ' + str(self.server_port))
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
                    host_ip = ''
                    try:
                        host_ip = socket.gethostbyname(host_name)
                        self.debug('Server IP address resolved to: ' + host_ip)
                        host_port = 8080
                        if url.group('port') is not None:
                            host_port = url.group('port')
                        self.debug('Server port number: ' + str(host_port))
                        self.server_addr = host_ip
                        self.server_port = host_port
                        self.server = (self.server_addr, str(self.server_port))
                    except socket.gaierror:
                        self.debug('Could not resolve host name: ' + host_name)

            else:
                self.debug('Invalid address format: ' + str(self.server_addr))
                valid = False

        if valid:
            self.router = (self.server_addr, 3000)

            self.run()

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
            self.debug('Could not resolve path in URL: ' + self.url)

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
        # Initialize socket and send request to router
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pkt = packet.UDPPacket(pkt_type=1,
                               seq_num=1,
                               peer_ip=self.server_addr,
                               peer_port=self.server_port,
                               data=str(rqst))
        self.debug('Built packet:\r\n\r\n' + str(pkt), True)

        # Send packet to router
        self.socket.sendto(pkt.to_bytes(), self.router)
        self.debug('Packet sent to router at: ' + str(self.router[0])
                   + ':' + str(self.router[1])
                   + ' (size = ' + str(pkt.len()) + ')')

    def recv(self):
        # Wait for a reply from the server
        resp, origin = self.socket.recvfrom(BUFFER_SIZE)
        if self.output is not None:
            with open(self.output, 'a') as file:
                file.write(origin)
                file.write(resp)

        return resp, origin

    def run(self):
        # Build request
        rqst = self.build_rqst()

        # Handle timeout
        try:
            self.send_rqst(rqst)
            self.socket.settimeout(self.timeout)

            # Receive server response
            resp, origin = self.recv()
            self.debug('Received response:\r\n\r\n' + resp, True)
            self.debug('Origin: ' + origin)

        except socket.timeout:
            self.debug('Connection timed out')

        finally:
            # Close connection
            self.debug('Closing connection')
            self.socket.close()

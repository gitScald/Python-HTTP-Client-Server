import argparse
import httpc_lib
import socket

DESCRIPTION = 'httpc is a simple cURL-like HTTP client application.'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('rqst_type',
                        action='store',
                        choices=['get', 'GET', 'post', 'POST'],
                        help='Request type (GET or POST)')
    parser.add_argument('-v',
                        action='store_true',
                        help="Enables verbose output")
    parser.add_argument('-o',
                        action='store',
                        help='Writes output to the specified file')
    parser.add_argument('--h',
                        action='store',
                        help='Specifies headers to attach to the requestr')
    parser.add_argument('-d',
                        action='store',
                        help='Specifies inline data to include in the request body')
    parser.add_argument('-f',
                        action='store',
                        help='Specifies data from a file to include in the request body')
    parser.add_argument('url',
                        action='store',
                        help='Specifies the URL to send the request to')
    parser.add_argument('-t',
                        action='store',
                        help='Specifies the timeout value')

    args = parser.parse_args()
    server = httpc_lib.HTTPClient(rqst_type=args.rqst_type,
                                  verbose=args.v,
                                  output=args.o,
                                  headers=args.h,
                                  data_inline=args.d,
                                  data_file=args.f,
                                  url=args.url,
                                  timeout=args.t)

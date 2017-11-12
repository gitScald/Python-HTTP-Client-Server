import argparse
import httpfs_lib


DESCRIPTION = 'httpfs is a simple HTTP file server application.'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-v',
                        action='store_true',
                        help="Enables verbose output")
    parser.add_argument('-p',
                        action='store',
                        default=8080,
                        type=int,
                        help='Specifies the port number for the server')
    parser.add_argument('-d',
                        action='store',
                        help='Specifies the working directory for the server')
    parser.add_argument('-w',
                        action='store_true',
                        help='Adds a delay to read/write operations for concurrency tests')

    args = parser.parse_args()
    server = httpfs_lib.FileServer(args)

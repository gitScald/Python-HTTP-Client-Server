# this file will run all three of:
# httpc.py
# httpfs.py
# router.go

import httpc_lib

CMD = {'GET': 'GET',
       'POST': 'POST'}

if __name__ == '__main__':
    client = httpc_lib.HTTPClient(CMD['GET'],
                                  server_addr='httpbin.org/get',
                                  server_port=80)

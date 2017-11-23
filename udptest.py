import subprocess
import sys

PATH = {'ROUTER': 'windows/router_x86.exe',
        'HTTPFS': 'httpfs.py',
        'HTTPC': 'httpc.py'}

if __name__ == '__main__':
    subprocess.run(PATH['ROUTER'], shell=True)
    subprocess.run(['py', PATH['HTTPFS'], '-v'], shell=True)
    subprocess.run(['py', PATH['HTTPC'], 'get', '-v', '192.168.1.100:8080/'], shell=True)

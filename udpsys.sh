#!/bin/bash
windows/router_x86.exe &
sleep 1
py httpfs.py -v &
sleep 1
py httpc.py get -v 192.168.1.100:8080/ &
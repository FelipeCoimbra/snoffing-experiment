#!/usr/bin/env python

import socket
import sys

TCP_IP = '127.0.0.1'
tcp_port = 23
BUFFER_SIZE = 256 

# Read user port
if len(sys.argv) > 1:
    tcp_port = int(sys.argv[1])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, tcp_port))
s.listen(1)

try:
    conn, addr = s.accept()
    print('Connection address: ', addr)
    
    while 1:
        data = conn.recv(BUFFER_SIZE)
        if not data: break
        print("Received data: ", data)
        conn.send(data)  # echo
except KeyboardInterrupt:
    try:
        conn.close()
    except NameError:
        pass
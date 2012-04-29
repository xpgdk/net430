#!/usr/bin/python

import socket
import sys

# A UDP server

# Set up a UDP server
UDPSock = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)

# Listen on port 21567
# (to all IP addresses on this system)
listen_addr = ("",5000)
UDPSock.bind(listen_addr)

# Report on all data packets received and
# where they came from in each case (as this is
# UDP, each may be from a different source and it's
# up to the server to sort this out!)
while True:
        data,addr = UDPSock.recvfrom(1500)
        sys.stdout.write(data)

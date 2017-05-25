#!/usr/bin/python3

# Script that relays packets with low TTL to spoofing server
# To be run on server which the traceroute should be faked of

import socket
import binascii
import daemon

INTERFACE_NAME = "eth0" # Interface to listen on for packets with low TTL
TTL_LIMIT = 10 # Count of hops to be relayed
SPOOFING_ENDPOINT = ("127.0.0.1", 1406) # Address of UDP socket on spoofing server where frames with low TTL are relayed to (Socket should not be accessible to third parties!)

receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
receiver.bind((INTERFACE_NAME, 0))

sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

context = daemon.DaemonContext()
context.files_preserve = [receiver, sender]

with context:
    while True:
        data = receiver.recv(8192)
        if data[12:14] == b'\x08\x00':
            ip_version = 4
        elif data[12:14] == b'\x86\xdd':
            ip_version = 6
        else:
            continue
        ttl = data[22 if ip_version == 4 else 21]
        if ttl <= TTL_LIMIT:
            sender.sendto(data, SPOOFING_ENDPOINT)

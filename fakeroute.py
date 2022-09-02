#!/usr/bin/env python3

import argparse
import atexit
import binascii
import hashlib
import hmac
import ipaddress
import logging
import os
import select
import socket
import struct
import sys
import time
import traceback

import pyroute2
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded

ETH_P_IP = socket.htons(0x0800)
ETH_P_IP6 = socket.htons(0x86dd)

DEFAULT_ADDRESSES = [
    "217.115.147.245",  # Verfassungsschutz
    "8.44.101.6",  # NSA
    "153.31.119.142",  # FBI
    "198.81.129.68",  # CIA
    "195.99.147.120",  # GCHQ
    "95.173.136.75",  # Kremlin
    "193.168.15.36",  # NATO
    "199.209.154.0",  # US Army
    "199.208.239.67",  # Pentagon
    "41.134.107.17",  # DoD South Africa

    "2001:4860:4860::8888",  # Google DNS
    "2a03:2880:f11c:8083:face:b00c:0:25de",  # Facebook
    "2610:20:6005:13::49",  # NIST
    "2001:19e8:d::100",  # Department of Transportation
    "2001:4d0:8300:401::189",  # NASA
    "2607:f6d0:0:925a::ab43:d7c8",  # Stanford
    "2001:500:89::53",  # ICANN
]


def nftables_ttl_lte_expression(family, ttl):
    """
    Generate NFTables rules that drop packets with a TTL/hop limit <= ttl

    :param family: AF_INET or AF_INET6
    :param ttl: The TTL.
    :return: Rule that can be supplied to pyroute2.
    """
    offset = 8 if family == socket.AF_INET else 7
    return [
        # Load TTL
        {'attrs': [('NFTA_EXPR_NAME', 'payload'),
                   ('NFTA_EXPR_DATA',
                    {'attrs': [('NFTA_PAYLOAD_DREG', 1),
                               ('NFTA_PAYLOAD_BASE', 1),
                               ('NFTA_PAYLOAD_OFFSET', offset),
                               ('NFTA_PAYLOAD_LEN', 1)]})]},
        # Compare
        {'attrs': [('NFTA_EXPR_NAME', 'cmp'),
                   ('NFTA_EXPR_DATA',
                    {'attrs': [('NFTA_CMP_SREG', 1),
                               ('NFTA_CMP_OP', 3),
                               ('NFTA_CMP_DATA', {'attrs': [('NFTA_DATA_VALUE', bytes([ttl]))]})]})]},
        # Drop
        {'attrs': [('NFTA_EXPR_NAME', 'immediate'),
                   ('NFTA_EXPR_DATA',
                    {'attrs': [('NFTA_IMMEDIATE_DREG', 0),
                               ('NFTA_IMMEDIATE_DATA',
                                {'attrs': [('NFTA_DATA_VERDICT',
                                            {'attrs': [('NFTA_VERDICT_CODE', 0)]})]})]})]}
    ]


def convert2addr(obj, default_port=None):
    """
    Convert a string, tuple or list IP endpoint representation to an (ip_address, port) tuple"

    :param obj: The object to convert.
    :param default_port: A default port for the service to be used if no port can be deduced.
    :return: The resulting tuple.
    """
    if (isinstance(obj, tuple) or isinstance(obj, list)) and len(obj) == 2:
        if isinstance(obj[0], str):
            return ipaddress.ip_address(obj[0]), obj[1]
        else:
            return obj[0], obj[1]
    elif isinstance(obj, str):
        obj = obj.strip()

        # Maybe it can just be converted to an IP address
        try:
            ip = ipaddress.ip_address(obj)
            return ip, default_port
        except ValueError:
            pass

        if obj[0] == '[' and ']' in obj:  # [<ipv6addr>]:<port> format
            rest = obj[obj.index(']') + 1:]
            if len(rest) == 0:
                return ipaddress.ip_address(obj[1:]), default_port
            if rest[1] != ':':
                raise ValueError
            return ipaddress.ip_address(obj[1:]), int(rest[1:])
        elif ':' in obj:  # <ipv4addr>:<port> format
            split = obj.split(':', 1)
            return ipaddress.ip_address(split[0]), int(split[1])
    raise ValueError


def convert2addr_str(obj, default_port=None):
    ip, port = convert2addr(obj, default_port)
    return str(ip), port


def get_ip_version(payload):
    return payload[0] >> 4


def get_ttl(payload):
    ttl_offset = 8 if get_ip_version(payload) == 4 else 7
    return payload[ttl_offset]


def get_src_addr(payload):
    return ipaddress.ip_address(payload[12:12 + 4] if get_ip_version(payload) == 4 else payload[8:8 + 16])


def get_dst_addr(payload):
    return ipaddress.ip_address(payload[16:16 + 4] if get_ip_version(payload) == 4 else payload[24:24 + 16])


def get_packet_info(payload):
    return get_ip_version(payload), get_src_addr(payload), get_dst_addr(payload), get_ttl(payload)


def nfgen_family_to_ip_version(family):
    if family == socket.AF_INET:
        return 4
    elif family == socket.AF_INET6:
        return 6
    return None


class LocalSpoofer:
    """
    Send spoofed IP packets from the local machine.
    """

    def __init__(self):
        self.sockets = {
            4: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW),
            6: socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
        }

    def spoof(self, packet):
        version, _, dst, _ = get_packet_info(packet)
        self.sockets[version].sendto(packet, (str(dst), 0))


class RemoteSpoofer:
    """
    Forward packets to be spoofed to a remote machine. This is used if your fake traceroute target is located in a data
    center with egress filtering, which prevents IP address spoofing.
    """

    def __init__(self, addr, key=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.remote_addr = addr
        self.key = key

    def spoof(self, packet):
        data = b''
        sig_len = 0
        sig = b''
        timestamp = struct.pack('!Q', int(time.time()))
        if self.key is not None:
            sig = hmac.new(self.key, timestamp + packet, hashlib.sha256).digest()
            sig_len = len(sig)
        data += bytes([sig_len]) + sig + timestamp + packet
        self.socket.sendto(data, self.remote_addr)


class SpoofingService(LocalSpoofer):
    """
    This is a remote spoofing service to be run in a data center without egress filtering.
    """

    def __init__(self, bind, key=None):
        super().__init__()
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind = bind
        self.key = key

    def run(self):
        self.receiver.bind(self.bind)
        while True:
            data, address = self.receiver.recvfrom(0xFFFF)
            # noinspection PyStringFormat
            logging.debug('Spoofer received packet from %s:%d' % address)
            if len(data) < 1:
                continue
            sig_len = data[0]
            if len(data) < sig_len + 1:
                continue
            msg = data[1 + sig_len:]
            if self.key is not None:
                sig = data[1:1 + sig_len]
                sig_cmp = hmac.new(self.key, msg, hashlib.sha256).digest()
                if not hmac.compare_digest(sig, sig_cmp):
                    # noinspection PyStringFormat
                    logging.warning('Invalid signature from %s:%d' % address)
                    continue
            if len(msg) < 8:
                continue
            (timestamp,) = struct.unpack('!Q', msg[0:8])
            now = time.time()
            if not (now - 60 <= timestamp <= now + 60):
                # noinspection PyStringFormat
                logging.warning('Replay protection timestamp mismatch from %s:%d' % address)
                continue
            packet = msg[8:]
            try:
                self.spoof(packet)
            except:
                logging.error(traceback.format_exc())


class TracerouteFakeTarget:
    """
    This is to be run on the server for which the traceroute should be faked. This class uses raw sockets to capture
    incoming IP addresses and sets up firewall rules that drop packets with a low TTL, so that the operating system does
    interfere with our fake replies. When packets with a low TTL are captured, a spoofer class is called to generate
    fake replies.
    """

    def __init__(self, addresses, spoofer):
        self.spoofer = spoofer
        self.addrs = {
            4: [],
            6: []
        }
        for addr in addresses:
            ip_addr = ipaddress.ip_address(addr)
            self.addrs[ip_addr.version].append(ip_addr)

        atexit.register(self.delete_firewall_rules)
        if self.num_addresses(4) > 0:
            self.setup_firewall(socket.AF_INET)
        if self.num_addresses(6) > 0:
            self.setup_firewall(socket.AF_INET6)

    def setup_firewall(self, nfgen_family):
        # noinspection PyUnresolvedReferences
        with pyroute2.NFTables(nfgen_family=nfgen_family) as nft:
            nft.table('add', name='fakeroute')
            nft.chain('add', table='fakeroute', name='fakeroute', type='filter', hook='input')
            num_addresses = self.num_addresses(nfgen_family_to_ip_version(nfgen_family))
            exp = nftables_ttl_lte_expression(nfgen_family, num_addresses)
            nft.rule('add', table='fakeroute', chain='fakeroute', expressions=(exp,))

    def delete_firewall_rules(self, *_, **__):
        if self.num_addresses(4) > 0:
            # noinspection PyUnresolvedReferences
            with pyroute2.NFTables(nfgen_family=socket.AF_INET) as nft:
                nft.table('del', name='fakeroute')
        if self.num_addresses(6) > 0:
            # noinspection PyUnresolvedReferences
            with pyroute2.NFTables(nfgen_family=socket.AF_INET6) as nft:
                nft.table('del', name='fakeroute')

    def num_addresses(self, version):
        return len(self.addrs[version])

    def spoof(self, payload):
        version, src, dst, ttl = get_packet_info(payload)
        spoof_addr = str(self.addrs[version][ttl - 1])
        if spoof_addr is None:
            return
        if version == 4:
            packet = IP(src=spoof_addr, dst=src) / ICMP(type=0xb, code=0) / payload
        else:
            packet = IPv6(src=spoof_addr, dst=src) / ICMPv6TimeExceeded() / payload
        self.spoofer.spoof(bytes(packet))

    def run(self):
        sockets = []
        if self.num_addresses(4) > 0:
            sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, ETH_P_IP))
        if self.num_addresses(6) > 0:
            sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, ETH_P_IP6))
        while True:
            read, _, _ = select.select(sockets, [], [])
            for r in read:
                payload, _ = r.recvfrom(0xffff)
                version, src, dst, ttl = get_packet_info(payload)
                logging.debug('IPv%d packet from %s to %s, TTL %d' % (version, src, dst, ttl))
                if ttl <= self.num_addresses(version):
                    self.spoof(payload)


def main():
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO'))

    parser = argparse.ArgumentParser(description='Fake traceroute generator')
    parser.add_argument('--hops', help='Path to file containing IPv4 and IPv6 addresses')
    parser.add_argument('--remote', help='IP:port of remote spoofing service')
    parser.add_argument('--spoofer', help='IP:port to launch a spoofing service locally')
    parser.add_argument('--key', help='HMAC-SHA256 signing key for remote spoofing authentication in hex format')
    args = parser.parse_args()
    addresses = DEFAULT_ADDRESSES
    if args.hops is not None:
        with open(args.hops, 'r') as f:
            addresses = [line.strip() for line in f.readlines() if line.strip() != '']

    key = None
    if args.key is not None:
        try:
            key = binascii.unhexlify(args.key)
        except binascii.Error:
            logging.warning('Key is not in hex format. It will still be used as a text key.')
            key = args.key.encode()

    if args.spoofer is None:
        spoofer = LocalSpoofer() if not args.remote else RemoteSpoofer(convert2addr_str(args.remote), key)
        faker = TracerouteFakeTarget(addresses, spoofer)
        faker.run()
    else:
        if args.remote is not None:
            sys.stderr.write('The options --remote and --spoofer cannot be used together.\n')
            sys.exit(1)
        spoofer = SpoofingService(convert2addr_str(args.spoofer), key)
        spoofer.run()


if __name__ == '__main__':
    main()

#!/bin/sh

iptables -I INPUT -m ttl --ttl-lt 11 -j DROP   # Drop IPv4 packets with TTL <= 10
ip6tables -A INPUT -m hl --hl-lt 11 -j DROP    # Drop IPv6 packets with HL <= 10

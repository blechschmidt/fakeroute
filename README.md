# fakeroute
Fakeroute allows you to insert fake IPv4 and IPv6 hops between the last real hop and your server by making use of IP address spoofing. It only supports Linux. Obviously, this is just a fun project. Do not use it for anything serious.

## Setup
Install the dependencies using `pip install -r requirements.txt`. Run `sudo python fakeroute.py` on the machine, for which you want to spoof the TTL.

You can supply the path to a text file with custom IP addresses to be spoofed using `--hops`.
The file can contain IPv4 and IPv6 addresses, one per line.

To test the script, you can set up a virtual machine with a bridged network interface, such that it obtains its own IP via DHCP, and traceroute the IP of the host.

Most ISPs will not allow you to spoof IP addresses nowadays. You can still make use of fakeroute by externalizing the spoofing process. To this end, start fakeroute with the `--spoofer` option, which expects `IP:port` to listen on, in a data center that allows spoofing. Then, on the machine for which you want to fake the traceroute, supply fakeroute with the remote endpoint (`IP:port`) of the spoofer using `--remote`. You can add an HMAC `--key` to not allow everyone to use your spoofing service.

```
usage: fakeroute.py [-h] [--hops HOPS] [--remote REMOTE] [--spoofer SPOOFER] [--key KEY]

Fake traceroute generator

options:
  -h, --help         show this help message and exit
  --hops HOPS        Path to file containing IPv4 and IPv6 addresses
  --remote REMOTE    IP:port of remote spoofing service
  --spoofer SPOOFER  IP:port to launch a spoofing service locally
  --key KEY          HMAC-SHA256 signing key for remote spoofing authentication in hex format
```

## How does it work?
IP packet headers contain a one byte time to live (TTL, IPv4) or hop limit (HL, IPv6) field which is supposed to be decreased by every router on the packet's path in order to prevent infinite circulations. Initially, the sender populates the packet with a sufficiently large value. Most routers signal the expiry of the TTL by replying with an ICMP "TTL expired" packet to the packet sender. Tracerouting works by sending out packets with increasing TTL. The first router will drop the packet with TTL 1 and send an ICMP reply, the second router will drop the packet with TTL 2 and so on. By simply dropping all packets with a TTL below a certain threshold N at the last hop, it will appear as if N hops, that do not reply with ICMP packets, had been inserted. The `fakeroute.py` script uses a raw socket to capture packets with low TTL and relay them to a server in a [data center without egress filtering](https://spoofer.caida.org/as_stats.php) (i.e. where packets with spoofed source IP address are not filtered). The `spoof.py` script receives these low TTL packets and generates ICMP replies for them from fake source IP addresses.

## Screenshot
![Screenshot](https://cysec.biz/projects/fakeroute/screenshot1.png)

#!/usr/bin/env python3
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump, sniff
from scapy.all import Packet
from scapy.all import Ether, IPv6, UDP, TCP

def get_if(host_iface):
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if host_iface in i:
            iface=i
            break
    if not iface:
        print("Cannot find " + host_iface + " interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('protocol', type=str, help="The protocol to use, TCP or UDP")
    parser.add_argument('sport', type=int, help="The source TCP/UDP port to use")
    parser.add_argument('dport', type=int, help="The destination TCP/UDP port to use")
    parser.add_argument('--host_iface', type=str, default="enp7s0", help='The host interface to use')

    args = parser.parse_args()
    iface = get_if(args.host_iface)

    print("Sending on interface {} to IP addr {}".format(iface, str(args.ip_addr)))
    if args.protocol == "TCP" or args.protocol == "tcp":
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')/IPv6(dst=args.ip_addr)/TCP(sport=args.sport, dport=args.dport)
    else:
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')/IPv6(dst=args.ip_addr)/UDP(sport=args.sport, dport=args.dport)


    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

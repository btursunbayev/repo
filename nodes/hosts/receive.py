#!/usr/bin/env python3
import argparse
import sys

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

def handle_pkt(pkt, thismac):
    if pkt[Ether].dst == thismac:
        if TCP in pkt:
            print("Received TCP")
            sys.stdout.flush()
        elif UDP in pkt:
            print("Received UDP")
            sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host_iface', type=str, default="enp7s0", help='The host interface use')
    args = parser.parse_args()

    iface = get_if(args.host_iface)
    mac = get_if_hwaddr(iface)
    print(("sniffing on %s" % iface))
    sys.stdout.flush()

    sniff(iface = iface,
          prn = lambda x: handle_pkt(x,mac))

if __name__ == '__main__':
    main()

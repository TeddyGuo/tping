import argparse
from scapy.all import *
import random
import time

# Random seed initialization
random.seed(time.time())

def argument_parser_init():
    parser = argparse.ArgumentParser(prog="tping",
                                     description="send common packets to network hosts")
    parser.add_argument("destination", type=str,
                        help="An address of destination")
    parser.add_argument("-6", "--ipv6", dest="is_ipv6", action="store_true",
                        help="Recognize the address of destination to be IPv6 (default: IPv4 address)")
    parser.add_argument("-1", "--tcp", dest="is_tcp", action="store_true",
                        help="Send out the TCP packet (default: ICMP protocol)")
    parser.add_argument("-2", "--udp", dest="is_udp", action="store_true",
                        help="Send out the UDP packet (default: ICMP protocol)")
    parser.add_argument("-c", "--count", dest="count", type=int, default=0,
                        help="Stop after sending (and receiving) count response packets")
    parser.add_argument("-p", "--dport", dest="dport", type=int, default=0,
                        help="Set destination port (default: 0)")
    parser.add_argument("-s", "--sport", dest="sport", type=int, default=random.randint(1, 65535),
                        help="Set source port (default: random)")
    return parser

class Tping(object):
    dest = None
    is_ipv6 = None
    is_tcp = None
    is_udp = None
    count = None
    dport = None
    sport = None

    def __init__(self, args):
        # Argument initialization
        self.dest = args.destination
        self.is_ipv6 = args.is_ipv6
        self.is_tcp = args.is_tcp
        self.is_udp = args.is_udp
        self.count = args.count
        self.dport = args.dport
        self.sport = args.sport

    def print_args(self):
        print("Destination: " + str(self.dest))
        print("Is IPv6 enabled: " + str(self.is_ipv6))
        print("Is TCP enabled: " + str(self.is_tcp))
        print("Is UDP enabled: " + str(self.is_udp))
        print("Count: " + str(self.count))
        print("Destination port: " + str(self.dport))
        print("Source port: " + str(self.sport))
    
    def run(self):
        raw_ip = None
        if self.is_ipv6 == True:
            # TODO: check the destination format
            raw_ip = IPv6(dst=self.dest)
        else:
            raw_ip = IP(dst=self.dest)

        packet = None
        if self.is_tcp == True:
            packet = raw_ip/TCP(dport=self.dport, sport=self.sport)
        elif self.is_udp == True:
            packet = raw_ip/UDP(dport=self.dport, sport=self.sport)
        else:
            # Default pakcet is ICMP
            if self.is_ipv6 == True:
                packet = raw_ip/ICMPv6()
            else:
                packet = raw_ip/ICMP()

        # send out the packet
        if self.count != 0:
            resp = srloop(packet, count=self.count)
        else:
            resp = srloop(packet)

        print(resp)

if __name__ == "__main__":
    parser = argument_parser_init()
    args = parser.parse_args()

    tping = Tping(args)

    tping.print_args()

    tping.run()

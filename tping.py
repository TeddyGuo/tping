import sys
import random
import time
from functools import *
import argparse
from scapy.all import *

# Random seed initialization
random.seed(time.time())

"""
    The argparse customization is so cool!
    Reference: https://stackoverflow.com/questions/25295487/python-argparse-value-range-help-message-appearance
"""
def range_type(astr, minimum, maximum):
    value = int(astr)
    if minimum <= value <= maximum:
        return value
    else:
        raise argparse.ArgumentTypeError("value not in range %s-%s" % (minimum, maximum))

def argument_parser_init():
    parser = argparse.ArgumentParser(prog="tping",
                                     description="send common packets to network hosts")
    parser.add_argument("destination", type=str,
                        help="An address of destination")
    parser.add_argument("-a", "--spoof", dest="source", metavar="source", type=str,
                        help="Set a fake source address")
    parser.add_argument("-6", "--ipv6", dest="is_ipv6", action="store_true",
                        help="Recognize the address of destination to be IPv6 (default: IPv4 address)")
    # Layer 4 protocol mutual-exclusive group
    l4_group = parser.add_mutually_exclusive_group()
    l4_group.add_argument("-1", "--tcp", dest="is_tcp", action="store_true",
                        help="Send out the TCP packet (default: ICMP protocol)")
    l4_group.add_argument("-2", "--udp", dest="is_udp", action="store_true",
                        help="Send out the UDP packet (default: ICMP protocol)")
    ###### End of L4 protocol m-exclusive group ######
    parser.add_argument("-c", "--count", dest="count", metavar="count",
                        type=partial(range_type, minimum=1, maximum=sys.maxsize), default=0,
                        help="Stop after sending (and receiving) count response packets")
    parser.add_argument("-p", "--dport", dest="dport", metavar="dest port",
                        type=partial(range_type, minimum=1, maximum=65535), default=0,
                        help="Set destination port (default: %(default)s)")
    parser.add_argument("-s", "--sport", dest="sport", metavar="source port",
                        type=partial(range_type, minimum=1, maximum=65535), default=random.randint(1, 65535),
                        help="Set source port (default: random)")
    return parser

class Tping(object):
    dst = None
    src = None
    is_ipv6 = None
    is_tcp = None
    is_udp = None
    count = None
    dport = None
    sport = None

    def __init__(self, args):
        # Argument initialization
        self.dst = args.destination
        self.src = args.source
        self.is_ipv6 = args.is_ipv6
        self.is_tcp = args.is_tcp
        self.is_udp = args.is_udp
        self.count = args.count
        self.dport = args.dport
        self.sport = args.sport

    def print_args(self):
        print("Destination: " + str(self.dst))
        print("Source: " + str(self.src))
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
            raw_ip = IPv6(dst=self.dst)
        else:
            raw_ip = IP(dst=self.dst)

        if self.src != None:
            # TODO: check the source format
            raw_ip.src = self.src

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

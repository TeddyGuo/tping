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
    parser.add_argument("-A", "--ACK", dest="is_ack", action="store_true",
                        help="Set TCP ACK flag")
    parser.add_argument("-i", "--interval", dest="interval", default=1, type=int, metavar="interval",
                        help="""Wait the specified number of seconds between sending each packet." 
                             "--interval X set wait to X seconds,--interval uX set wait to X micro seconds."  
                             "The default is to wait one second between each packet.""" )
    parser.add_argument("-u", "--micro", dest="is_microsec", action="store_true",
                        help="To make interval in microseconds (by default interval is 1 second)")

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
    is_ack = None
    interval = None
    is_microsec = None

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
        self.is_ack = args.is_ack
        self.interval = args.interval
        self.is_microsec = args.is_microsec

    def print_args(self):
        print("Destination: " + str(self.dst))
        print("Source: " + str(self.src))
        print("Is IPv6 enabled: " + str(self.is_ipv6))
        print("Is TCP enabled: " + str(self.is_tcp))
        print("Is UDP enabled: " + str(self.is_udp))
        print("Count: " + str(self.count))
        print("Destination port: " + str(self.dport))
        print("Source port: " + str(self.sport))
        print("Is TCP ACK enabled: " + str(self.is_ack))
        print("Is interval set: " + str(self.interval))
        print("Is interval set in microsecond: " + str(self.is_microsec))
   
    def run(self):
        l3_pkt = None
        if self.is_ipv6 == True:
            # TODO: check the destination format
            l3_pkt = IPv6(dst=self.dst)
        else:
            l3_pkt = IP(dst=self.dst)

        if self.src != None:
            # TODO: check the source format
            l3_pkt.src = self.src

        l4_pkt = None
        if self.is_tcp == True:
            l4_pkt = l3_pkt/TCP(dport=self.dport, sport=self.sport)
            if self.is_ack == True:
                l4_pkt.flags="A"
        elif self.is_udp == True:
            l4_pkt = l3_pkt/UDP(dport=self.dport, sport=self.sport)
        else:
            # Default pakcet is ICMP
            if self.is_ipv6 == True:
                l4_pkt = l3_pkt/ICMPv6()
            else:
                l4_pkt = l3_pkt/ICMP()

        # send out the packet
        if self.interval !=1 and self.is_microsec ==True:
            if self.count != 0:
                resp = send(l4_pkt, count=self.count, loop=1, inter=self.interval/1000000)
            else:
                resp = send(l4_pkt, loop=1, inter=self.interval/1000000)
        elif self.interval !=1 and self.is_microsec ==False:
            if self.count != 0:
                resp = send(l4_pkt, loop=1, count=self.count, inter=self.interval)
            else:
                resp = send(l4_pkt, loop=1, inter=self.interval)
        elif self.interval ==1:
            if self.count != 0:
                resp = send(l4_pkt, loop=1, count=self.count)
            else:
                resp = send(l4_pkt, loop=1)

        print(resp)

if __name__ == "__main__":
    parser = argument_parser_init()
    args = parser.parse_args()

    tping = Tping(args)

    tping.print_args()

    tping.run()

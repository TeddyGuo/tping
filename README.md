# tping

## Description

The main purpose for the tool is to support a tool like **hping3** but support IPv6.

We know **hping3** is a good tool.

However, it has a really big defect since it cannot support IPv6 testing.

As an networking engineer, I always need to test some cases based on both IPv4 and IPv6.

That is, I decided to develop such a tool based on the well-known **Scapy** module.

Of course, it still has a lot to be improved.

Therefore, I would try my best to develop the tool and it can be a good practice for me as well.

## Usage
```
usage: tping [-h] [-a source] [-6] [-1 | -2] [-c count] [-p dest port]
             [-s source port] [-A] [-i interval] [-u]
             destination

send common packets to network hosts

positional arguments:
  destination           An address of destination

optional arguments:
  -h, --help            show this help message and exit
  -a source, --spoof source
                        Set a fake source address
  -6, --ipv6            Recognize the address of destination to be IPv6
                        (default: IPv4 address)
  -1, --tcp             Send out the TCP packet (default: ICMP protocol)
  -2, --udp             Send out the UDP packet (default: ICMP protocol)
  -c count, --count count
                        Stop after sending (and receiving) count response
                        packets
  -p dest port, --dport dest port
                        Set destination port (default: 0)
  -s source port, --sport source port
                        Set source port (default: random)
  -A, --ACK             Set TCP ACK flag
  -i interval, --interval interval
                        Wait the specified number of seconds between sending
                        each packet." "--interval X set wait to X seconds,--
                        interval uX set wait to X micro seconds." "The default
                        is to wait one second between each packet.
  -u, --micro           To make interval in microseconds (by default interval
                        is 1 second)
```

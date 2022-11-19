"""
Copyright (c) 2021, Nils Rothaug
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived
from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from scapy.all import *
from time import sleep
from tqdm import tqdm # Progress bar
import socket
import argparse

parser = argparse.ArgumentParser(description='Send Industrial Protocol packets from trace over UDP.')
parser.add_argument("tracefile", help="Name of the PCAP file", type=str)
parser.add_argument("ip", help="IP address to send the packets to", type=str)
parser.add_argument("port", help="UDP port to send the packets to", type=int)
parser.add_argument("-v6", "--ipv6", help="Whether the address is an IPv6 address", action="store_true")
parser.add_argument("-d", "--delay", help="The deleay between packets in milliseconds", type=int, default=250)
args = parser.parse_args()

pcap = rdpcap(args.tracefile)
numpkts = len(pcap)
numignored = 0
numsent = 0

if args.ipv6:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((args.ip, args.port))

with tqdm(total=numpkts) as pbar:
    for pkt in pcap:
        if Raw in pkt:
            payload = pkt[Raw].load
            sock.send(payload)
            numsent += 1
            if args.delay:
                sleep(args.delay / 1000)
        else:
            numignored += 1

        pbar.update(1)

sock.close()
print(f"Done. Sent {numsent} application layer packets. Ignored {numignored} packets from trace without payload")
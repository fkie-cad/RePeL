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
import argparse

parser = argparse.ArgumentParser(description='Check whether fragmented app-layer packets are interspaced with other packets')
parser.add_argument("tracefile", help="Name of the PCAP file", type=str)
parser.add_argument("-f", "--fraglen", help="Maximum fragment length to check for", type=int, default=7)
parser.add_argument("-n", "--number", help="Number of packets to compare to", type=int, default=10)
args = parser.parse_args()

pcap = rdpcap(args.tracefile)
numtotal = 0
numfrags = 0
numbroken = 0

history = []
index = 0

for pkt in pcap:
    if Raw in pkt:

        payload = pkt[Raw].load
        if len(payload) <= args.fraglen:
            numfrags += 1

            # Check packets in history
            sep = len(history) - 1
            for old in history[:-1]:
                if old[IP].src == pkt[IP].src \
                and old[IP].dst == pkt[IP].dst \
                and old[TCP].sport == pkt[TCP].sport \
                and old[TCP].dport == pkt[TCP].dport \
                and old[TCP].seq + len(old[Raw].load) == pkt[TCP].seq:

                    numbroken += 1
                    print(f"Trace[{index}]: Found fragment TCP.seq={pkt[TCP].seq} belonging to TCP.seq={old[TCP].seq},",
                    f"separation: {sep} packets, fragment length: {len(payload)}")
            sep -= 1

        history.append(pkt)
        if len(history) > args.number:
            history.pop(0)

        numtotal += 1
    index += 1

print(f"Done. Processed {numtotal} packets. Found {numfrags} fragmented packets, with {numbroken} being broken up.")
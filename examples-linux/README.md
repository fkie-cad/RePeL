# RePeL examples for Linux
Example programs and helper scripts for the Retrofittable Protection Library (RePeL) on Linux.

## Build

Run `git submodule update --init` after cloning to initialize the `tinydtls` submodule.

Then, for example, start a simulation in [Cooja](https://docs.contiki-ng.org/en/develop/doc/tutorials/Cooja-simulating-a-border-router.html) with a mote running the RePeL example program `tcp_eval_server` for [Contiki-NG](https://github.com/contiki-ng/contiki-ng).
Build `contiki-ng/tools/serial-io/tunslip6` and add a serial server socket to the mote in Cooja as described [here](https://docs.contiki-ng.org/en/develop/doc/tutorials/Cooja-simulating-a-border-router.html).
 Run `tunslip6` together with `scripts/logs_to_json.py` from this repo, to collect the mote's logs and measurements:
 ```
 sudo <contiki-ng>/tools/serial-io/tunslip6 -v0 -a 127.0.0.1 fd00::1/64 | python3 logs_to_json.py <output file>
 ```

 Send Modbus TCP packets from a PCAP file to the mote to start RePeL's performance evaluation on those packets:

 ```
 python3 scripts/send_tcp_trace.py -v6 <pcap file> <mote ip> 1234
 ```
The mote prints its IP when `tunslip6` is connected.

## Example programs

### sane_io
Static library with utility functions that simplify TCP socket and commandline input handling.
Used by the `udp_gateway` example.

### scripts
Python 3 helper scripts for evaluating RePeL's example programs for Contiki-NG.
The scripts use the [Scapy](https://scapy.net/) library to handle PCAP packet traces.
Some also require the `tqdm` module to display a progress bar.

#### check_fragmented_packets.py
For a TCP packet trace, checks whether application-layer packets fragmented into multiple TCP segments are interspaced with other packets.

#### logs_to_json.py
Use with the RePeL example programs for Contiki-NG on the output of Contiki-NG's `tunslip6`, which receives their log messages.
The script filters the `tunslip6` output for the example program's log messages and writes them to a json file.

#### repair_pcap.py
Similar to `check_fragmented_packets.py`. Reorders fragmented application-layer packets and writes the result into a new PCAP file.

#### send_tcp_trace.py
Sends application layer packets from a PCAP packet trace to a destination via TCP.
Use with the `tcp_eval_server` RePeL example program for Contiki-NG.

#### send_udp_trace.py
Sends application layer packets from a PCAP packet trace to a destination via UDP.
Use with the `udp_eval_server` RePeL example program for Contiki-NG.


### udp_gateway
Evaluation program to measure the performance deploying RePeL on a network
gateway that handles integrity protection for an embedded device, rather than
deploying the library on the device itself.

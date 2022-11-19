# RePeL examples for Contiki-NG

Example programs the Retrofittable Protection Library (RePeL) for the Contiki-NG operating system.

## Build

Set up the Contiki-NG [build environment](https://docs.contiki-ng.org/en/develop/doc/getting-started/Toolchain-installation-on-Linux.html) and add the
`repel` and `examples-contiki` directories as `os/lib/repel` and `examples/repel`
to the source tree.

Use Contiki-NG's [build system](https://github.com/contiki-ng/contiki-ng/wiki/The-Contiki%E2%80%90NG-build-system) to build individual examples, e.g.:
```
cd examples/repel/bitstring_test
make TARGET=native
```

The examples can either run on embedded hardware (tested with Zolertia Z1 and Zoul), or in the simulator [Cooja](https://docs.contiki-ng.org/en/develop/doc/tutorials/Running-Contiki-NG-in-Cooja.html).
Most examples require a border router to send logs and measurements to. This requires running `tunslip6` from `contiki-ng/tools/serial-io`. For details, refer to the Contiki-NG documentation for connecting to [real hardware](https://docs.contiki-ng.org/en/develop/doc/tutorials/RPL-border-router.html) or [Cooja](https://docs.contiki-ng.org/en/develop/doc/tutorials/Cooja-simulating-a-border-router.html).

Target platforms differ in their memory constraints and the amount of heap memory required to run example programs. To successfully build and run an example, `HEAPMEM_CONF_ARENA_SIZE` in the example's `project_conf.h` might need adjustment. RePeL informs about running out of heap memory with the error _"Out of heapmem, can't allocate block of size ..."_.


## Example programs

### bitstring_test
Test program which tests the correctness of the `bitstring_t` type used for bit shifting.
Also runs on target `native`.
Does not require a border router.

### eval_macpattern
Test program to evaluate RePeL's performance in relation to the number of fields / segments the MAC is split into when protecting packets. Uses RePeL's `split_parser`.

### eval_noncebits
Test program to evaluate RePeL's performance depending on the number of nonce (number used once) bits that are embedded in a packet.

### eval_pktlen
Test program to evaluate RePeL's performance depending on the length of packets to be protected.
Uses RePeL's `hmac` module for integrity protection.

### hw_sha2_hash_benchmark
Tests the performance of the TinyDTLS software and Zolertia Zoul hardware SHA2 hash function implementations (not HMAC) in isolation.
Only runs on target `zoul`.

### hw_sha2_test
Test program to compare RePeL's performance when using the TinyDTLS software SHA256 HMAC implementation versus using the Zolertia Zoul's hardware acceleration. Only runs on target `zoul`.

### modbus_tcp_receiver
Waits for Modbus TCP packets with embedded MAC, restores the original packets, re-embeds the MAC and sends them back to the sender.
Does not require a border router.

### modbus_tcp_sender
Counterpart to <tt>modbus_tcp_sender</tt>: Protects and sends packets to a hardcoded receiver, waits for the response, reverses
the embedding in the response and checks whether they match the sent packet.
Does not require a border router.

__Requires to supply a packet trace in `modbus_tcp_trace.h` in order to build.__

### tcp_eval_server
Evaluation program to measure the performance of RePeL on packets received via TCP.
Allows to supply a packet trace from a computer.

__Requires `os/lib/repel/tcp_socket.patch`__, which fixes Contiki-NG's TCP stack, for correct operation on packets split over multiple TCP segments at the time of writing.

### test_memoverhead
Test program that measures the RAM overhead overhead of TinyDTLS or RePeL over a skeleton TCP-receiving Contiki-NG application.

### udp_eval_server
Evaluation program to measure the performance of RePeL on packets received via UDP.
Allows to supply a packet trace from a computer.
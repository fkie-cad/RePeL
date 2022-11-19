#ifndef MODBUS_TCP_TRACE_H_
#define MODBUS_TCP_TRACE_H_

static inline unsigned short modbus_pkt_len(unsigned char const* start) {
    return ((start[4] << 8) | start[5]) + 6; // 6 header bytes
}

unsigned char const modbus_tcp_trace[] = {
#error Provide a Modbus TCP packet trace
/* Import, e.g., from Wireshark */
};

#endif
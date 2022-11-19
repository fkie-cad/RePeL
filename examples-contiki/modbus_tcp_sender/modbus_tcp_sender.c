/*
 * Copyright (c) 2021, Nils Rothaug
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *        Sends protected Modbus TCP packet traces to hardcoded IP, waits for response and compares it with trace.
 * \author
 *         Nils Rothaug
 */

#include "contiki.h"
#include "sys/log.h"

#include "process.h"
#include "tcp-socket.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6-nbr.h"

#include <stdbool.h>
#include <stdio.h> /* For printf() */

#include <repel/repel.h>
#include <repel/repel_log.h>

#include "modbus_tcp_trace.h"

#define TCP_PORT 512

#define TCP_BUF_LEN 256

typedef enum {
    CREATED = 0,
    CONNECTED,
    SENT,
    RECEIVED
} SockState;

static SockState sock_state = CREATED;
static uint16_t pktlen;
static uint8_t const* pkt, *next = modbus_tcp_trace;

static repel_connection_t session;

/*---------------------------------------------------------------------------*/
PROCESS(sender_proc, "Modbus TCP Sender Process");
AUTOSTART_PROCESSES(&sender_proc);
/*---------------------------------------------------------------------------*/

void onauth(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) cbdata;
    (void) packet;
    (void) packet_len;
    info("Packet verified, protection level: %d, protocol had %s nonce",
        (int) result.protection_level,
        result.nonce_embedded? "no" : ""
        );
    if(result.packet_loss) {
        warn("Lost %d packets", (int) result.packet_loss);
    }
}

void onfail(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) cbdata;
    (void) packet;
    (void) packet_len;
    info("Packet NOT verified, protection level: %d, protocol had %s nonce",
        (int) result.protection_level,
        result.nonce_embedded? "no" : ""
        );
    if(result.packet_loss) {
        warn("Lost %d packets", (int) result.packet_loss);
    }
}

/**
 *
 * @return Number of bytes to leave in the buffer (and submitted to next call?)
 */
int cb_sock_data(struct tcp_socket* sock, void *nil, const uint8_t *input, int len) {
    info("Receiving %d bytes", len);

    /**
     * repel_authenticate modifies (restores) the packet in place,
     * thus we modify the TCP receive buffer that is declared const.
     * However, these modified contents are discarded after we return
     * (as indicated by our return value), so removing the const modfier
     * and changes in the buffer have no effect.
     */
    int32_t plen = repel_authenticate(session, (uint8_t*) input, len, &onauth, &onfail, NULL);
    if(plen == 0) {
        error("Parsing error");
        return len; /* Keep bytes */
    }
    if(plen < 0) {
        warn("Not a full packet");
        return len; /* Keep bytes */
    }
    if(memcmp(input, pkt, plen)) {
        warn("Mismatch between sent and received packet.");
    }
    sock_state = RECEIVED;
    process_poll(&sender_proc);

    return len - plen; /* Discard received pkt */
}

/**
 * Called when tcp socket state changes
 */
void cb_sock_event(struct tcp_socket* sock, void *nil, tcp_socket_event_t event) {
  switch(event) {
    case TCP_SOCKET_CONNECTED:
        info("Connected");
        sock_state = CONNECTED;
        process_poll(&sender_proc);
        break;
    case TCP_SOCKET_TIMEDOUT:
        error("Timeout");
        break;
    default:
      break;
  }
}

PROCESS_THREAD(sender_proc, ev, data) {

    static struct tcp_socket sock;
    static uip_ipaddr_t ip;

    static uint8_t tcp_input_buf[TCP_BUF_LEN];
    static uint8_t tcp_output_buf[TCP_BUF_LEN];
    static uint8_t pkt_buf[TCP_BUF_LEN];

    static uint8_t keys[2][16] = {
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 },
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x35 }
    };

PROCESS_BEGIN();
    session = repel_create_connection(&modbus_tcp_parser, &hmac_module, 3);
    repel_set_keys(session, keys);

    uip_ip6addr(&ip, 0xfe80, 0, 0, 0, 0xc30c, 0x0, 0x0, 0x1);
    //ip = *uip_ds6_nbr_get_ipaddr(uip_ds6_nbr_head());

    tcp_socket_register(&sock, NULL, tcp_input_buf, TCP_BUF_LEN, tcp_output_buf, TCP_BUF_LEN, cb_sock_data, cb_sock_event);
    tcp_socket_connect(&sock, &ip, TCP_PORT);

    info("Connecting...");
    PROCESS_WAIT_EVENT_UNTIL(sock_state == CONNECTED);

    do {
        pkt = next;

        pktlen = ((pkt[4] << 8) | pkt[5]) + 6; /* MBAP Length does not include all of header */
        next = pkt + pktlen;

        /* Trace is (hopefully) in flash, copy to RAM */
        memcpy(pkt_buf, pkt, pktlen);
        if(0 == repel_embed(session, pkt_buf, pktlen)) {
            warn("Error when embedding MAC");
        }

        info("Sending packet...");
        tcp_socket_send(&sock, pkt_buf, pktlen);
        sock_state = SENT;

        PROCESS_WAIT_EVENT_UNTIL(sock_state == RECEIVED);


    } while(next - modbus_tcp_trace < sizeof(modbus_tcp_trace));

    info("All packets received, exiting...");

    tcp_socket_unregister(&sock);
    repel_destroy_connection(session);

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

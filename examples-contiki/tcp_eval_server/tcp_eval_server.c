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
 * Evaluation program to measure the performance of RePeL on packets
 * received via TCP. Allows to supply a packet trace from a computer.
 * Requires os/lib/repel/tcp_socket.patch, which fixes Contiki-NG's TCP stack,
 * for correct operation on packets split over multiple TCP segments
 * at the time of writing.
 *
 * \author
 * Nils Rothaug
 */
#include "contiki.h"
#include "sys/log.h"

#include "process.h"
#include "net/ipv6/tcp-socket.h"

#include <string.h>

#include <repel/repel.h>
#include <repel/repel_log.h>
#include <services/rpl-border-router/rpl-border-router.h>

#define REPEL_PARSER modbus_tcp_parser
#define REPEL_NONCE_BITS 0

#define TCP_PORT 1234


/*---------------------------------------------------------------------------*/
PROCESS(server_proc, "TCP Server");
AUTOSTART_PROCESSES(&server_proc);
/*---------------------------------------------------------------------------*/

uint8_t tcpbuf[UIP_BUFSIZE];
/**
 * Copy received data to buffer to compare with original data
 */
uint8_t pktbuf[UIP_BUFSIZE];
bool tcp_closed = false;

repel_connection_t repel_con;
auth_result_t parsed_auth;
uint32_t pkts_success = 0;
uint32_t pkts_error = 0;
uint32_t pkts_split = 0;

static void auth_cb(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) cbdata;
    (void) packet;

    parsed_auth = result;
}

void tcp_event(struct tcp_socket* sock, void *nil, tcp_socket_event_t event) {
  (void) sock;
  (void) nil;
  switch(event) {
    case TCP_SOCKET_CONNECTED:
        info("Connected");
        break;
    case TCP_SOCKET_ABORTED: // fall through
    case TCP_SOCKET_TIMEDOUT: // fall through
    case TCP_SOCKET_CLOSED:
        info("Closing");
        tcp_closed = true;
        process_poll(&server_proc);
        break;
    default:
      break;
  }
}

static int tcp_recv(struct tcp_socket* sock, void *nil, const uint8_t *input, int len) {
    (void) sock;
    (void) nil;

    memcpy(pktbuf, input, len);
    int32_t plen = _eval_parse_pkt_len(repel_con, pktbuf, len);
    if(plen < 0) {
        warn("Incomplete packets, waiting for %d more bytes, have %d bytes", (int) -plen, len);
        pkts_split++;

        return len;
    }
    if(plen == 0) {
        error("Invalid packet, dumping buffer");
        log_packet(pktbuf, len);
        pkts_error++;

        return 0;
    }

    uint16_t datalen = (uint16_t) plen;
    uint16_t macbits = repel_embed(repel_con, pktbuf, datalen);
    if(!macbits) {
        error("Embed parsing error, skipping packet with length %u", (unsigned int) datalen);
        log_packet(pktbuf, datalen);
        pkts_error++;

        return len - datalen;
    }

    plen = repel_authenticate(repel_con, pktbuf, datalen, &auth_cb, &auth_cb, NULL);
    if(plen <= 0) {
        error("Authenticate parsing error, length: %u, parsed: %d", (unsigned int) datalen, (int) plen);
        pkts_error++;

        return len - datalen;
    }
    if(plen != datalen) {
        error("Unexpected packet length, skipping %d bytes", (int) (datalen - plen));
        pkts_error++;
    } else if(parsed_auth.protection_level <= 0 || parsed_auth.protection_level != macbits) {
        error("Packet authentication error, embedded: %d, extracted: %d",
            (int) macbits, (int) parsed_auth.protection_level);
        pkts_error++;
    } else {
        pkts_success++;
    }
    if(parsed_auth.packet_loss) {
        error("Packet loss, lost: %d", (int) parsed_auth.packet_loss);
    }
    if(memcmp(input, pktbuf, datalen)) {
        log_packet_diff(input, pktbuf, datalen);
    }

    return len - datalen;
}

PROCESS_THREAD(server_proc, ev, data) {
    static struct tcp_socket sock;
    static uint8_t keys[2][16] = {
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 },
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 }
    };

PROCESS_BEGIN();

    PROCESS_WAIT_EVENT_UNTIL(ev == RPL_EVENT_CONNECTED);
    repel_con = repel_create_connection(&REPEL_PARSER, &hmac_module, REPEL_NONCE_BITS);
    repel_set_keys(repel_con, keys);

    tcp_socket_register(&sock, NULL, tcpbuf, UIP_BUFSIZE, NULL, 0, &tcp_recv, &tcp_event);
    tcp_socket_listen(&sock, TCP_PORT);

    PROCESS_WAIT_UNTIL(tcp_closed);

    info("Done. %lu packets authenticated, %lu packet errors, %lu split packets",
        (unsigned long) pkts_success,
        (unsigned long) pkts_error,
        (unsigned long) pkts_split);
    tcp_socket_unregister(&sock);
    repel_destroy_connection(repel_con);

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

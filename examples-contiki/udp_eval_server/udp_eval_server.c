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
 * received via UDP. Allows to supply a packet trace from a computer.
 *
 * \author
 * Nils Rothaug
 */
#include "contiki.h"
#include "sys/log.h"

#include "process.h"
#include "net/ipv6/udp-socket.h"

#include <string.h>

#include <repel/repel.h>
#include <repel/repel_log.h>
#include <services/rpl-border-router/rpl-border-router.h>

#define REPEL_PARSER modbus_tcp_parser
#define REPEL_NONCE_BITS 0

#define UDP_PORT 1234


/*---------------------------------------------------------------------------*/
PROCESS(server_proc, "UDP Server");
AUTOSTART_PROCESSES(&server_proc);
/*---------------------------------------------------------------------------*/

/**
 * Copy received data to buffer to compare with original data
 */
uint8_t pktbuf[UIP_BUFSIZE];
repel_connection_t repel_con;
auth_result_t parsed_auth;

static void auth_cb(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) cbdata;
    (void) packet;

    parsed_auth = result;
}

static void udp_recv(struct udp_socket *c, void *ptr,
    const uip_ipaddr_t *source_addr, uint16_t source_port,
    const uip_ipaddr_t *dest_addr, uint16_t dest_port,
    const uint8_t *data, uint16_t datalen) {
    (void) c;
    (void) source_addr;
    (void) source_port;
    (void) dest_addr;
    (void) dest_port;

    memcpy(pktbuf, data, datalen);
    uint16_t macbits = repel_embed(repel_con, pktbuf, datalen);
    if(!macbits) {
        error("Embed parsing error, skipping packet");
        return;
    }

    int plen = repel_authenticate(repel_con, pktbuf, datalen, &auth_cb, &auth_cb, NULL);
    if(plen <= 0) {
        error("Authenticate parsing error, length: %d, parsed: %d", (int) datalen, (int) plen);
        return;
    }
    if(plen != datalen) {
        error("Unexpected packet length, skipping %d bytes", (int) (datalen - plen));
    }
    if(parsed_auth.protection_level <= 0 || parsed_auth.protection_level != macbits) {
        error("Packet authentication error, embedded: %d, extracted: %d",
            (int) macbits, (int) parsed_auth.protection_level);
    }
    if(parsed_auth.packet_loss) {
        error("Packet loss, lost: %d", (int) parsed_auth.packet_loss);
    }
    if(memcmp(data, pktbuf, datalen)) {
        log_packet_diff(data, pktbuf, datalen);
    }
}

PROCESS_THREAD(server_proc, ev, data) {

    static struct udp_socket sock;
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

    udp_socket_register(&sock, NULL, &udp_recv);
    udp_socket_bind(&sock, UDP_PORT);
    while(true) {
        PROCESS_WAIT_EVENT();
    }
    /* No deregistering */

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

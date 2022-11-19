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
 * Test program that measures the RAM overhead overhead of TinyDTLS
 * or RePeL over a skeleton TCP-receiving Contiki-NG application.
 *
 * \author
 * Nils Rothaug
 */
#include "contiki.h"

#include "process.h"
#include "net/ipv6/tcp-socket.h"

#include <stdio.h>

#include "heapmem.h"
#include "sys/stack-check.h"

#define REPEL_PARSER modbus_tcp_parser
#define REPEL_NONCE_BITS 0

#define TCP_PORT 1234


/*---------------------------------------------------------------------------*/
PROCESS(server_proc, "TCP Server");
AUTOSTART_PROCESSES(&server_proc);
/*---------------------------------------------------------------------------*/

uint8_t tcpin[UIP_BUFSIZE];
uint8_t tcpout[UIP_BUFSIZE];
bool tcp_closed = false;

struct tcp_socket sock;

#if WITH_TINYDTLS
#include "tinydtls.h"
#include "dtls-hmac.h"
#endif

#if WITH_REPEL
#include <repel/repel.h>

repel_connection_t repel_con;
uint8_t keys[2][16] = {
    { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
        0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 },
    { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
        0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 }
};
#endif

static void tcp_event(struct tcp_socket* sock, void *nil, tcp_socket_event_t event) {
  (void) sock;
  (void) nil;
  switch(event) {
    case TCP_SOCKET_ABORTED: // fall through
    case TCP_SOCKET_TIMEDOUT: // fall through
    case TCP_SOCKET_CLOSED:
        tcp_closed = true;
        process_poll(&server_proc);
        break;
    default:
      break;
  }
}

#if WITH_REPEL
static void send_cb(void* nil, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) result;
    (void) nil;

    tcp_socket_send(&sock, packet, packet_len);
}
#endif

static int tcp_recv(struct tcp_socket* sock, void *nil, const uint8_t *input, int len) {
    (void) sock;
    (void) nil;

#if WITH_REPEL
    /**
     * repel_authenticate modifies (restores) the packet in place,
     * thus we modify the TCP receive buffer that is declared const.
     * However, these modified contents should be discarded after we return
     * (as indicated by our return value), so removing the const modfier
     * and changes in the buffer have no effect.
     * On incomplete packets, authenticate performs no modifications.
     */
    int16_t bits = repel_embed(repel_con, (uint8_t*) input, len);
    int32_t plen = repel_authenticate(repel_con, (uint8_t*) input, len, send_cb, NULL, NULL);
    if(!bits || !plen) {
        printf("Invalid packet. embed(): %u, authenticate(): %u.",
            (unsigned int) bits,
            (unsigned int) plen);
    }
    return 0;
#else
    tcp_socket_send(sock, input, len);
    return 0;
#endif
}

PROCESS_THREAD(server_proc, ev, data) {
    static int32_t stack_usage;
    static heapmem_stats_t heapstats;

PROCESS_BEGIN();

#if WITH_REPEL
    repel_con = repel_create_connection(&REPEL_PARSER, &hmac_module, REPEL_NONCE_BITS);
    repel_set_keys(repel_con, keys);
#endif

    tcp_socket_register(&sock, NULL, tcpin, UIP_BUFSIZE, tcpout, UIP_BUFSIZE, &tcp_recv, &tcp_event);
    tcp_socket_listen(&sock, TCP_PORT);

    PROCESS_WAIT_UNTIL(tcp_closed);

    tcp_socket_unregister(&sock);

    /* For RePeL, heap allocation changes only during create and destroy */
    heapmem_stats(&heapstats);

#if WITH_REPEL
    repel_destroy_connection(repel_con);
#endif
    /* Only accurate if heapmem_stats does not influence measurements.
    But at least with the call to RePeL in between, that is a safe assumption */
    stack_usage = stack_check_get_usage();
    /* Else no heap memory is used, so measure here */
#if !WITH_REPEL
    heapmem_stats(&heapstats);
#endif

    /* We do not measure stack usage of the following, but that is intended. */

    printf("Stack usage: %lu\n"
            "Heap allocated: %llu\n"
            "Heap overhead: %llu\n"
            "Heap available: %llu\n"
            "Heap footprint: %llu\n"
            "Heap chunks: %llu\n",
            (unsigned long) stack_usage,
            (unsigned long long) heapstats.allocated,
            (unsigned long long) heapstats.overhead,
            (unsigned long long) heapstats.available,
            (unsigned long long) heapstats.footprint,
            (unsigned long long) heapstats.chunks);

#if WITH_TINYDTLS
// Just *something* to measure ROM impact of TinyDTLS
    dtls_hmac_context_t ctx;
    dtls_hmac_init(&ctx, NULL, 0);
    dtls_hmac_update(&ctx, NULL, 0);
/*Again, just *something* that does not crash and has a low memory overhead */
    dtls_hmac_finalize(&ctx, tcpin);
#endif
PROCESS_END();
}
/*---------------------------------------------------------------------------*/

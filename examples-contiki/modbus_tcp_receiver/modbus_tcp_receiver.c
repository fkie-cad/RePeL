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
 * A RePeL example program that listens for protected Modbus TCP packets, unpacks them,
 * again embeds a Mac in them and sends them back to the sender.
 *
 * \author
 * Nils Rothaug
 */

#include "contiki.h"
#include "sys/log.h"

#include "process.h"
#include "tcp-socket.h"
#include "net/ipv6/uip.h"

#include <stdbool.h>
#include <stdio.h> /* For printf() */

#include <repel/repel.h>
#include <repel/repel_log.h>

static repel_connection_t session;

#define TCP_PORT 512

#define TCP_BUF_LEN 256

/*---------------------------------------------------------------------------*/
PROCESS(server_proc, "Modbus TCP Receiver Process");
AUTOSTART_PROCESSES(&server_proc);
/*---------------------------------------------------------------------------*/

static bool disconnect = false;

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
    static unsigned int count = 0;
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

    /* Discarding const, same as above */
    uint16_t bits = repel_embed(session, (uint8_t*) input, plen);
    if(bits) {
        info("Embedded %u bits", (unsigned int) bits);
    } else {
        error("Embed error");
    }
    count++;
#if 0
    if(count % 3 == 0) {
        /* Fuzzing every third packet */
        ((uint8_t*) input)[9] ^= (uint8_t)  count;
    }
#endif
    tcp_socket_send(sock, input, plen);
    return len - plen;
}

/**
 * Called when tcp socket state changes
 */
void cb_sock_event(struct tcp_socket* sock, void *nil, tcp_socket_event_t event) {
  switch(event) {
    case TCP_SOCKET_CONNECTED:
        info("Connected");
        break;
    case TCP_SOCKET_ABORTED: // fall through
    case TCP_SOCKET_TIMEDOUT: // fall through
    case TCP_SOCKET_CLOSED:
        info("Disconnected");
        disconnect = true;
        process_poll(&server_proc);
        break;
    default:
      break;
  }
}

PROCESS_THREAD(server_proc, ev, data) {

    static struct tcp_socket sock;
    static uint8_t tcp_input_buf[TCP_BUF_LEN];
    static uint8_t tcp_output_buf[TCP_BUF_LEN];
    static uint8_t keys[2][16] = {
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x35 },
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 }
    };

PROCESS_BEGIN();

    session = repel_create_connection(&modbus_tcp_parser, &hmac_module, 3);
    repel_set_keys(session, keys);

    tcp_socket_register(&sock, NULL, tcp_input_buf, TCP_BUF_LEN, tcp_output_buf, TCP_BUF_LEN, cb_sock_data, cb_sock_event);
    tcp_socket_listen(&sock, TCP_PORT);

    info("Accepting connections...");
    PROCESS_YIELD_UNTIL(disconnect);

    tcp_socket_unregister(&sock);
    repel_destroy_connection(session);

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

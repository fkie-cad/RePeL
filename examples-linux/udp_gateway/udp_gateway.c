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
 * Evaluation program to measure the performance deploying RePeL on a network
 * gateway that handles integrity protection for an embedded device, rather than
 * deploying the library on the device itself.
 *
 * \author
 * Nils Rothaug
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <repel.h>
#include <repel_log.h>

#include <sane_tcp.h>

#define UDP_BUF_SIZE    1500

#define REPEL_EMBED true

#define REPEL_PARSER    modbus_tcp_parser
#define REPEL_HMAC      hmac_module
#define REPEL_NONCEBITS 0

uint8_t udp_buf[UDP_BUF_SIZE];

uint8_t keys[2][16] = {
    { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
        0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 }, /* send key */
    { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
        0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x35 } /* receive key */
};

tcp_socket_t insock, outsock;
repel_connection_t repel;
struct timespec recvd, sent;

#if !REPEL_EMBED

void auth_cb(void* nil, void* packet, uint16_t pktlen, auth_result_t res) {
    (void) nil;
    (void) res;

    clock_gettime(CLOCK_REALTIME, &sent);
    send(outsock.socket, packet, pktlen, 0);

    long double delay = (sent.tv_nsec - recvd.tv_nsec) / 1000.0; // microseconds
    delay += (sent.tv_sec - recvd.tv_sec) * 1000000.0;

    printf("{\n\t\"type\": \"sendtime\",\n\t\"label\": \"authenticate\",\n"
                "\t\"pktlen\": \"%u\",\n\t\"unit\": \"microsecond\",\n"
                "\t\"delay\": %Lf\n},\n",
                (unsigned int) pktlen, delay);
}

void inv_cb(void* nil, void* packet, uint16_t pktlen, auth_result_t res) {
    (void) nil;
    (void) res;

    clock_gettime(CLOCK_REALTIME, &sent);
    send(outsock.socket, packet, pktlen, 0);

    long double delay = (sent.tv_nsec - recvd.tv_nsec) / 1000.0; // microseconds
    delay += (sent.tv_sec - recvd.tv_sec) * 1000000.0;

    printf("{\n\t\"type\": \"sendtime\",\n\t\"label\": \"authenticate\",\n"
                "\t\"pktlen\": \"%u\",\n\t\"unit\": \"microsecond\",\n"
                "\t\"delay\": %Lf\n},\n",
                (unsigned int) pktlen, delay);

    error("Invalid packet");
}

#endif


int main(int argc, char** argv) {
    char* netport, *devip, *devport, *proto;
    enum IPversion ipv = IP_V4;

    switch(argc) {
        case 5:
            proto = argv[1];
            netport = argv[2];
            devip = argv[3];
            devport = argv[4];
            break;
        case 6:
            if(0 == strcmp(argv[1], "-v6")) {
                ipv = IP_V6;
                proto = argv[2];
                netport = argv[3];
                devip = argv[4];
                devport = argv[5];
                break;
            } // fallthrough
        default:
            printf("Usage %s: [-v6] [udp|tcp] <network port> <device ip> <device port>\n", argv[0]);
            exit(1);
            break;
    }

    if(0 == strcmp(proto, "udp")) {
        info("Using UDP. Stop program using ^C");
        if(!udp_server_open(&insock, netport, 0, ipv)) {
            error("Cannot open server socket");
            exit(1);
        }
        if(!udp_client_open(&outsock, devip, devport, ipv)) {
            error("Cannot open client socket");
            exit(1);
        }
    } else if(0 == strcmp(proto, "tcp")) {
        info("Using TCP. Stop program using ^C");
        if(!tcp_server_open(&insock, netport, 0, ipv)) {
            error("Cannot open server socket");
            exit(1);
        }
        if(!tcp_client_open(&outsock, devip, devport, ipv)) {
            error("Cannot open client socket");
            exit(1);
        }
    } else {
        error("Unknown protocol '%s', expected tcp or udp", proto);
        exit(1);
    }

    repel = repel_create_connection(&REPEL_PARSER, &REPEL_HMAC, REPEL_NONCEBITS);
    repel_set_keys(repel, keys);

    info("Start receiving");

    while(true) {
        ssize_t len = UDP_BUF_SIZE;
        struct sockaddr addr;
        socklen_t alen = sizeof(addr);

        len = recvfrom(insock.socket, udp_buf, UDP_BUF_SIZE, 0, &addr, &alen);
        /* We want highest res system clock */
        clock_gettime(CLOCK_REALTIME, &recvd);
        if(len > 0) {
#if REPEL_EMBED
            if(0 == repel_embed(repel, &udp_buf, len)) {
                error("Embed error");
            }
            clock_gettime(CLOCK_REALTIME, &sent);
            send(outsock.socket, &udp_buf, len, 0);

            long double delay = (sent.tv_nsec - recvd.tv_nsec) / 1000.0; // microseconds
            delay += (sent.tv_sec - recvd.tv_sec) * 1000000.0;

            printf("{\n\t\"type\": \"sendtime\",\n\t\"label\": \"embed\",\n"
                "\t\"pktlen\": \"%u\",\n\t\"unit\": \"microsecond\",\n"
                "\t\"delay\": %Lf\n},\n",
                (unsigned int) len, delay);
#else
            if(0 >= repel_authenticate(repel, &udp_buf, len, &auth_cb, &inv_cb, NULL)) {
                warn("Incomplete packet");
            }
#endif
        } else {
            break;
        }
    }

    error("Could not receive");
    tcp_close(&insock);
    tcp_close(&outsock);
    repel_destroy_connection(repel);
}
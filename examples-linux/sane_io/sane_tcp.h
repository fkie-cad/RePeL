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

#ifndef SANE_TCP_H_
#define SANE_TCP_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

typedef struct TcpSocket tcp_socket_t;
struct TcpSocket {
  int socket;
};

enum TCPShutdown {
  TCP_SHUT_READ = SHUT_RD,
  TCP_SHUT_WRITE = SHUT_WR,
  TCP_SHUT_BOTH = SHUT_RDWR
};

enum IPversion {
  IP_ANY = AF_UNSPEC,
  IP_V4 = AF_INET,
  IP_V6 = AF_INET6
};

bool tcp_client_open(tcp_socket_t* socket, const char* host, const char* service, enum IPversion ipv);

bool tcp_server_open(tcp_socket_t* socket, const char* service, size_t backlog, enum IPversion ipv);

bool tcp_server_accept(tcp_socket_t* server, tcp_socket_t* connection);

bool tcp_send_bytes(tcp_socket_t* socket, void* buffer, size_t count);

bool tcp_recv_bytes(tcp_socket_t* socket, void* buffer, size_t count);

/**
 * \param bsize In the size of the buffer, out the number of received bytes
 */
bool tcp_recv_some(tcp_socket_t* socket, void* buffer, size_t* bsize);

bool tcp_shutdown(tcp_socket_t* socket, enum TCPShutdown);

bool tcp_close(tcp_socket_t* socket);

bool udp_client_open(tcp_socket_t* socket, const char* host, const char* service, enum IPversion ipv);

bool udp_server_open(tcp_socket_t* socket, const char* service, size_t backlog, enum IPversion ipv);

#endif

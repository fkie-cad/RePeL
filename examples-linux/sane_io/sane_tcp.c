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

#include <string.h>

#define _POSIX_C_SOURCE 200809L
#include <unistd.h> // close()
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>  // getaddrinfo()

#include "sane_tcp.h"

bool tcp_client_open(tcp_socket_t* sock, const char* host, const char* service, enum IPversion ipv) {
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = ipv;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(host, service, &hints, &addresses)) {
        return false;
    }

    struct addrinfo* con = addresses;
    for(; con != NULL; con = con->ai_next) {
      sock->socket = socket(con->ai_family, con->ai_socktype, con->ai_protocol);
      if(sock->socket < 0) {
          continue;
      }

      if(connect(sock->socket, con->ai_addr, con->ai_addrlen)) {
          close(sock->socket);
          sock->socket = -1;
          continue;
      }

      break; // Success
    }

    freeaddrinfo(addresses);
    return con != NULL;
}

bool tcp_server_open(tcp_socket_t* sock, const char* service, size_t backlog, enum IPversion ipv) {
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = ipv;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if(getaddrinfo(NULL, service, &hints, &addresses)) {
        return false;
    }

    struct addrinfo* con = addresses;
    for(; con != NULL; con = con->ai_next) {
      sock->socket = socket(con->ai_family, con->ai_socktype, con->ai_protocol);
      if(sock->socket < 0) {
          continue;
      }

      if(bind(sock->socket, con->ai_addr, con->ai_addrlen)) {
          close(sock->socket); // Retry with next item
          sock->socket = -1;
          continue;
      }

      break; // Success
    }

    freeaddrinfo(addresses);

    if(sock->socket < 0 || listen(sock->socket, backlog)) {
        return false;
    }

    return true;
}

bool tcp_server_accept(tcp_socket_t* server, tcp_socket_t* connection) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(struct sockaddr_storage);

    connection->socket = accept(server->socket, (struct sockaddr*) &addr, &addrlen);
    return connection->socket >= 0;
}

bool tcp_send_bytes(tcp_socket_t* sock, void* buffer, size_t count) {
    int sent;
    uint8_t* buf = (uint8_t*) buffer;

    while(count > 0) {
        sent = send(sock->socket, buf, count, 0);
        if(sent <= 0) {
            return false;
        }
        buf += sent;
        count -= sent;
    }
    return true;
}

bool tcp_recv_bytes(tcp_socket_t* sock, void* buffer, size_t count) {
    int rcvd;
    uint8_t* buf = (uint8_t*) buffer;

    while(count > 0) {
        rcvd = recv(sock->socket, buf, count, 0);
        if(rcvd <= 0) {
            return false;
        }
        buf += rcvd;
        count -= rcvd;
    }
    return true;
}

bool tcp_recv_some(tcp_socket_t* sock, void* buffer, size_t* bsize) {
    int rcvd;
    uint8_t* buf = (uint8_t*) buffer;

    rcvd = recv(sock->socket, buf, *bsize, 0);
    if(rcvd <= 0) {
        *bsize = 0;
        return false;
    } else {
        *bsize = rcvd;
        return true;
    }
}

bool tcp_shutdown(tcp_socket_t* sock, enum TCPShutdown how) {
    return 0 == shutdown(sock->socket, how);
}

bool tcp_close(tcp_socket_t* sock) {
    if(sock->socket < 0) {
        return false;
    } else {
        close(sock->socket);
        return true;
    }
}

bool udp_client_open(tcp_socket_t* sock, const char* host, const char* service, enum IPversion ipv) {
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = ipv;
    hints.ai_socktype = SOCK_DGRAM;

    if(getaddrinfo(host, service, &hints, &addresses)) {
        return false;
    }

    struct addrinfo* con = addresses;
    for(; con != NULL; con = con->ai_next) {
      sock->socket = socket(con->ai_family, con->ai_socktype, con->ai_protocol);
      if(sock->socket < 0) {
          continue;
      }

      if(connect(sock->socket, con->ai_addr, con->ai_addrlen)) {
          close(sock->socket);
          sock->socket = -1;
          continue;
      }

      break; // Success
    }

    freeaddrinfo(addresses);
    return con != NULL;
}

bool udp_server_open(tcp_socket_t* sock, const char* service, size_t backlog, enum IPversion ipv) {
    (void) backlog; /* TODO unused, remove */

    struct addrinfo hints;
    struct addrinfo* addresses = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = ipv;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if(getaddrinfo(NULL, service, &hints, &addresses)) {
        return false;
    }

    struct addrinfo* con = addresses;
    for(; con != NULL; con = con->ai_next) {
      sock->socket = socket(con->ai_family, con->ai_socktype, con->ai_protocol);
      if(sock->socket < 0) {
          continue;
      }

      if(bind(sock->socket, con->ai_addr, con->ai_addrlen)) {
          close(sock->socket); // Retry with next item
          sock->socket = -1;
          continue;
      }

      break; // Success
    }

    freeaddrinfo(addresses);

    if(sock->socket < 0) {
        return false;
    }

    return true;
}
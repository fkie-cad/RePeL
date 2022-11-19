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

#ifndef SANE_POLL_H_
#define SANE_POLL_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <poll.h>

#include "sane_tcp.h"

enum TCPEvent {
  TCP_SEND = POLLOUT,
  TCP_RECV = POLLIN,
  TCP_CLOSE = POLLHUP,
  TCP_ERROR = POLLERR,
  TCP_SOCKINV = POLLNVAL
};

struct TcpPollList {
    unsigned int count;
    unsigned int slots;
    unsigned int blocksize;
    struct pollfd* poll_entries;
    struct CallbackEntry* callbacks;
};

/**
 * \param socket Pointer to a tcp_socket_t with the same file descriptor as the one that was added to the list
 */
typedef void tcp_socket_event_fn(tcp_socket_t* socket, enum TCPEvent event, void* context);

typedef struct TcpPollList tcp_poll_list_t;

tcp_poll_list_t* tcp_new_poll_list(unsigned int reserve);

void tcp_delete_poll_list(tcp_poll_list_t* list);

bool tcp_poll_list_add(tcp_poll_list_t* list, tcp_socket_t* socket, int poll_flags,
    tcp_socket_event_fn* callback, void* context);

/**
 * Removes a tcp_socket_t from the list that has the same file descriptor as the one supplied
 */
bool tcp_poll_list_rm(tcp_poll_list_t* list, tcp_socket_t* socket);

bool tcp_poll(tcp_poll_list_t* list, int timeoutms);

static inline unsigned int tcp_poll_list_len(tcp_poll_list_t* list) {
  return list->count;
}

static inline tcp_socket_t tcp_poll_list_get(tcp_poll_list_t* list, int index) {
  return (tcp_socket_t) { list->poll_entries[index].fd };
}

#endif
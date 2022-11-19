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

#include "sane_poll.h"

#include <string.h>
#include <stdlib.h>

struct CallbackEntry {
    tcp_socket_event_fn* fn;
    void* data;
};

tcp_poll_list_t* tcp_new_poll_list(unsigned int reserve) {
    tcp_poll_list_t* list = malloc(sizeof(tcp_poll_list_t));
    list->count = 0;
    list->slots = reserve;

    if(reserve > 0) {
        list->blocksize = reserve;
        list->poll_entries = malloc(reserve * sizeof(struct pollfd));
        list->callbacks = malloc(reserve * sizeof(struct CallbackEntry));
    } else {
        list->blocksize = 1;
        list->poll_entries = NULL;
        list->callbacks = NULL;
    }
    return list;
}

void tcp_delete_poll_list(tcp_poll_list_t* list) {
    if(list) {
        free(list->poll_entries);
        free(list->callbacks);
        free(list);
    }
}

bool tcp_poll_list_add(tcp_poll_list_t* list, tcp_socket_t* socket, int poll_flags,
    tcp_socket_event_fn* callback, void* context) {

    if(list->slots <= list->count) {
        unsigned int slots = list->slots + list->blocksize;
        void* memp, *memc;

        memp = realloc(list->poll_entries, slots * sizeof(struct pollfd));
        memc = realloc(list->poll_entries, slots * sizeof(struct CallbackEntry));
        if(!memp || !memc) {
            return false;
        }
        list->poll_entries = memp;
        list->callbacks = memc;
        list->slots = slots;
    }

    unsigned int num = list->count;
    list->poll_entries[num] = (struct pollfd) { socket->socket, poll_flags, 0};
    list->callbacks[num] = (struct CallbackEntry) { callback, context };

    list->count += 1;
    return true;
}

/**
 * Removes a tcp_socket_t from the list that has the same file descriptor as the one supplied
 */
bool tcp_poll_list_rm(tcp_poll_list_t* list, tcp_socket_t* socket) {
    unsigned int index = 0;
    for(index = 0; index < list->count; index++) {
        if(list->poll_entries[index].fd == socket->socket) {
            unsigned int rest = list->count - index;

            memcpy(&list->poll_entries[index],
                &list->poll_entries[index + 1],
                rest * sizeof(struct pollfd));
            memcpy(&list->callbacks[index],
                &list->callbacks[index + 1],
                rest * sizeof(struct CallbackEntry));

            list->count -= 1;

            unsigned int slots = list->slots;
            if(slots - list->count > list->blocksize) {
                void* memp, *memc;

                slots -= list->blocksize;
                memp = realloc(list->poll_entries, slots * sizeof(struct pollfd));
                memc = realloc(list->poll_entries, slots * sizeof(struct CallbackEntry));
                if(!memp || !memc) {
                    return true;
                }
                list->poll_entries = memp;
                list->callbacks = memc;
                list->slots = slots;
            }
            return true;
        }
    }

    return false;
}

bool tcp_poll(tcp_poll_list_t* list, int timeoutms) {
    int events = poll(list->poll_entries, list->count, timeoutms);
    if(events < 0) {
        return false;
    }
    unsigned int i = 0;
    while(events > 0 && i < list->count) {
        int flags = list->poll_entries[i].revents;
        if(flags) {
            tcp_socket_t s = { list->poll_entries[i].fd };
            void* data = list->callbacks[i].data;

            list->callbacks[i].fn(&s, flags, data);
            events--;
            break; /* May have modified the list */
        }
        i++;
    }
    return true;
}

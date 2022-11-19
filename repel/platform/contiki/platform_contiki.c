/*
 * Copyright (c) 2021, Nils Rothaug
 * Copyright (c) 2017, RISE SICS
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

#define LOGTAG "Heap Memory"
#include "platform.h"

#include "contiki.h"

/* IP-address logging */
#include "uiplib.h"
#include "uip-ds6.h"

/* Contiki NG has only 1 byte of heap memory by default, check configuration: */
#if HEAPMEM_CONF_ARENA_SIZE <= 1
#error "Repel module requires heap memory. Set HEAPMEM_CONF_ARENA_SIZE in project-conf.h accordingly"
#endif

#include "../../eval_timer.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#if REPEL_ENABLE_LOGGING

void* mem_alloc(size_t n) {
    void* mem = heapmem_alloc(n);

    if(mem == NULL) {
        error("Out of heapmem, can't allocate block of size %lu", (unsigned long) n);
    } else {
        heapmem_stats_t stats;
        heapmem_stats(&stats);
        debug("Alloc stats: %lu allocated, %lu free, %lu overhead, %lu footprint",
            (unsigned long) stats.allocated,
            (unsigned long) stats.available,
            (unsigned long) stats.overhead,
            (unsigned long) stats.footprint);
    }
    return mem;
}

void mem_free(void* ptr) {
    heapmem_free(ptr);
    heapmem_stats_t stats;
    heapmem_stats(&stats);
debug("Alloc stats: %lu allocated, %lu free, %lu overhead, %lu footprint",
            (unsigned long) stats.allocated,
            (unsigned long) stats.available,
            (unsigned long) stats.overhead,
            (unsigned long) stats.footprint);
}

void _pre_log_json(int lvl, char const* file) {
    char const* lvlstr;
    switch(lvl) {
        case LOG_LEVEL_INFO:
            lvlstr = "info";
            break;
        case LOG_LEVEL_WARN:
            lvlstr = "warn";
            break;
        case LOG_LEVEL_ERR:
            lvlstr = "error";
            break;
        case LOG_LEVEL_DBG:
            /* Fall through */
        default:
            lvlstr = "debug";
            break;
    }

    printf("{\n\t\"type\": \"log\",\n\t\"level\": \"%s\",\n\t\"file\": \"%s\",\n\t\"message\": \"", lvlstr, file);
}

void _post_log_json() {
    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}

void do_startup_logging() {
    /* Copied from rpl-border-router.c */
    uint8_t state;
    int i;
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        char buf[UIPLIB_IPV6_MAX_STR_LEN];

        state = uip_ds6_if.addr_list[i].state;
        if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
            uiplib_ipaddr_snprint(buf, sizeof(buf), &uip_ds6_if.addr_list[i].ipaddr);
            info("IPv6 address %s", buf);
        }
    }
}

void _log_pkt_json(char const* file, uint8_t const* pkt, uint16_t len) {
    printf("{\n\t\"type\": \"packet\",\n\t\"file\": \"%s\",\n\t\"length\": \"%u\",\n\t\"hex\": \"", file, (unsigned int) len);
    while(len > 0) {
        printf("%x ", *pkt);
        pkt++;
        len--;
    }
    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}

void _log_pktdiff_json(char const* file, uint8_t const* pkt1, uint8_t const* pkt2, uint16_t len) {
    printf("{\n\t\"type\": \"packetdiff\",\n\t\"file\": \"%s\",\n\t\"length\": \"%u\",\n\t\"hex\": \"", file, (unsigned int) len);
    uint16_t diff = 0;
    while(len > 0) {
        if(*pkt1 == *pkt2) {
            printf("%x ", (unsigned int) *pkt1);
        } else {
            printf("[%x|%x] ", (unsigned int) *pkt1, (unsigned int) *pkt2);
            diff++;
        }
        pkt1++;
        pkt2++;
        len--;
    }
    printf("\",\n\t\"diffbytes\": \"%d", (unsigned int) diff);
    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}

#else /* REPEL_ENABLE_LOGGING */

void* mem_alloc(size_t n) {
    void* mem = heapmem_alloc(n);
    return mem;
}

void mem_free(void* ptr) {
    heapmem_free(ptr);
}

#endif
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
 * Modbus TCP parser.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 25.08.2021
 */

#include "../repel_modules.h"
#include "../repel_log.h"

#include <string.h>

#include "platform.h"
#include "../bitstring.h"
#include "../eval_timer.h"

/**********************************************************
 *            Parameters to configure parser              *
 **********************************************************/

#ifndef MODBUS_TCP_REUSE_TID_BITS
/* 16 concurrent Transactions at max as per specification */
#define MODBUS_TCP_REUSE_TID_BITS 12
#endif

#ifndef MODBUS_TCP_IS_CLIENT
/* Whether device has client role on connection. Server does not remap Transaction Ids */
#define MODBUS_TCP_IS_CLIENT true
#endif

#ifndef MODBUS_TCP_REUSE_UNIT_ID
#define MODBUS_TCP_REUSE_UNIT_ID    true
#endif


#if MODBUS_TCP_REUSE_TID_BITS >= 16
#error Cant reuse that many Transaction Idnetifier Bits
#endif

#define MBAP_AND_FUNCTION_LEN   8

#if MODBUS_TCP_REUSE_TID_BITS > 0
static bufsize_t const tid_map_len = POW2(16 - MODBUS_TCP_REUSE_TID_BITS);
#else
static bufsize_t const tid_map_len = 1;
#endif

struct ModbusTCPState {
    /**
     * Transaction Ids are remapped to the array indices.
     * The transaction id zero is mapped to the value in tid0_index.
     * All other zero map entries are unused.
     */
    #if MODBUS_TCP_REUSE_TID_BITS > 0
    uint16_t transaction_map[POW2(16 - MODBUS_TCP_REUSE_TID_BITS)];
    #else
    uint16_t transaction_map[1]; /* unused */
    #endif

    uint16_t tid0_index;
};

uint16_t _map_tid(struct ModbusTCPState* state, uint16_t tid) {
    uint16_t ireserved = state->tid0_index;

    if(ireserved < tid_map_len) {
        return ireserved;
    }

    for(uint16_t i = 0; i < tid_map_len; i++) {
        if(i != ireserved && state->transaction_map[i] == 0) {
            if(tid == 0) {
                state->tid0_index = i;
            } else {
                state->transaction_map[i] = tid;
            }
            return i;
        }
    }
    error("Modbus TCP Client parser: Transaction Id Map is full.");
    return tid % tid_map_len; /* Keep lower ID bits */
}

uint16_t _unmap_tid(struct ModbusTCPState* state, uint16_t mapid) {
    uint16_t tid =  state->transaction_map[mapid];

    /* Hit empty entry */
    if(tid == 0) {
        if(mapid == state->tid0_index) {
            /* Was not empty but stored TID is 0 */
            state->tid0_index = tid_map_len;
            return 0;
        } else {
            error("Modbus TCP Client parser: Unknown Map Id 0x%x. Treating as Transaction Id.", mapid);
            return mapid;
        }
    } else {
        state->transaction_map[mapid] = 0;
        return tid;
    }
}

void* modbus_tcp_create(bitcount_t* max_embed_bits) {
    struct ModbusTCPState* state = (struct ModbusTCPState*) mem_alloc(sizeof(struct ModbusTCPState));
    if(!state) {
        return NULL;
    }
    memset(state->transaction_map, 0, tid_map_len);
    state->tid0_index = tid_map_len;

    *max_embed_bits = 16 + MODBUS_TCP_REUSE_TID_BITS;

    #if MODBUS_TCP_REUSE_UNIT_ID
        *max_embed_bits += 8;
    #endif

    return state;
}

void modbus_tcp_destroy(void* self) {
    mem_free(self);
}

parse_result_t modbus_tcp_parse(void* self, in_buffer_t packet, bufsize_t buflen, repel_mode_t mode) {
    eval_timer_measure_mod("begin parse");
    pkt_from(packet);
    UNUSED(self);
    UNUSED(mode);

    parse_result_t res;
    res.packet_has_nonce = false;

    /* Fail if Length field is missing */
    parse_fail_on_minlen(6, buflen);

    /* Parse Modbus Length field in bytes 4-5 */
    res.pktlen = bitstring_peek_u16(&pkt, 4*8, 16);
    res.pktlen += 6; /* TID, PID and Length field do not count to pkt len in MBAP */
    parse_fail_on_minlen(res.pktlen, buflen);

    /* There is a full packet in the buffer */
    res.embed_bits = 16 + MODBUS_TCP_REUSE_TID_BITS;

    #if MODBUS_TCP_REUSE_UNIT_ID
        res.embed_bits += 8;
    #endif

    eval_timer_measure_mod("end parse");
    return res;
}

void modbus_tcp_embed(void* self, inout_buffer_t packet, bufsize_t pktlen, in_buffer_t macbuf) {
    eval_timer_measure_mod("begin embed");
    pkt_from(packet);
    mac_from(macbuf);
    UNUSED(self);
    UNUSED(pktlen);

    /* Transaction Identifier */
    #if MODBUS_TCP_REUSE_TID_BITS > 0
    bitstring_copy_u16(&pkt, &mac, MODBUS_TCP_REUSE_TID_BITS);
    bitstring_skip(&pkt, 16 - MODBUS_TCP_REUSE_TID_BITS);

    #else /* MODBUS_TCP_REUSE_TID_BITS <= 0 */
    bitstring_skip(&pkt, 16);
    #endif

    /* Protocol Identifier */
    bitstring_copy_u16(&pkt, &mac, 16);
    /* Length */
    bitstring_skip(&pkt, 16);

    #if MODBUS_TCP_REUSE_UNIT_ID
    /* Unit Identifier */
    bitstring_copy_u8(&pkt, &mac, 8);
    #endif
    eval_timer_measure_mod("end embed");
}

void modbus_tcp_extract(void* self, inout_buffer_t packet, bufsize_t pktlen, out_buffer_t macbuf) {
    eval_timer_measure_mod("begin extract");
    pkt_from(packet);
    mac_from(macbuf);
    UNUSED(self);
    UNUSED(pktlen);

    /* Transaction Identifier */
    #if MODBUS_TCP_REUSE_TID_BITS > 0
    bitstring_copy_u16(&mac, &pkt, MODBUS_TCP_REUSE_TID_BITS);
    bitstring_skip(&pkt, 16 - MODBUS_TCP_REUSE_TID_BITS);

    #else /* MODBUS_TCP_REUSE_TID_BITS <= 0 */
    bitstring_skip(&pkt, 16);
    #endif

    /* Protocol Identifier */
    bitstring_copy_u16(&mac, &pkt, 16);
    /* Length */
    bitstring_skip(&pkt, 16);

    #if MODBUS_TCP_REUSE_UNIT_ID
    /* Unit Identifier */
    bitstring_copy_u8(&mac, &pkt, 8);
    #endif
    eval_timer_measure_mod("end extract");
}

void modbus_tcp_restore(void* self, inout_buffer_t packet, bufsize_t pktlen, repel_mode_t mode) {
    eval_timer_measure_mod("begin restore");
    state_from(struct ModbusTCPState, self);
    pkt_from(packet);
    UNUSED(pktlen);
    UNUSED(mode);

    /* Transaction Identifier */
    #if MODBUS_TCP_REUSE_TID_BITS > 0
    /* Only client remaps */
    #if MODBUS_TCP_IS_CLIENT
    /* Perform TID unmapping in verified and perform MAC calculation with mapped TID when receiving.
        When sending, calculate MAC with mapped TID, perform mapping in restore. */
    if(mode == EMBED) {
        uint16_t tid = bitstring_peek_u16(&pkt, 0, 16);
        uint16_t mapid = _map_tid(state, tid);
        bitstring_push_u16(&pkt, 0, MODBUS_TCP_REUSE_TID_BITS);
        bitstring_push_u16(&pkt, mapid, 16 - MODBUS_TCP_REUSE_TID_BITS);
    } else {
        bitstring_push_u16(&pkt, 0, MODBUS_TCP_REUSE_TID_BITS);
        bitstring_skip(&pkt, 16 - MODBUS_TCP_REUSE_TID_BITS);
    }
    #else
    UNUSED(state);
    /* Server expects small TIDs from client */
    /* Erase MAC bits if any (if not, then 0 anyway) */
    bitstring_push_u16(&pkt, 0, MODBUS_TCP_REUSE_TID_BITS);
    bitstring_skip(&pkt, 16 - MODBUS_TCP_REUSE_TID_BITS);
    #endif
    #else /* MODBUS_TCP_REUSE_TID_BITS <= 0 */
    UNUSED(state);
    bitstring_skip(&pkt, 16);
    #endif

    /* Protocol Identifier */
    bitstring_push_u16(&pkt, 0, 16);
    /* Length */
    bitstring_skip(&pkt, 16);

    #if MODBUS_TCP_REUSE_UNIT_ID
    /* Unit Identifier */
    bitstring_push_u8(&pkt, 255, 8);
    #endif
    eval_timer_measure_mod("end restore");
}

void modbus_tcp_verified(void* self, inout_buffer_t packet, bufsize_t pktlen) {
    eval_timer_measure_mod("begin verified");
    state_from(struct ModbusTCPState, self);
    pkt_from(packet);
    UNUSED(pktlen);

    /* Transaction Identifier */
    #if MODBUS_TCP_REUSE_TID_BITS > 0 && MODBUS_TCP_IS_CLIENT
    /* Unmap TID only after MAC was calculated as server MAC uses mapped TID */
    uint16_t mapid = bitstring_peek_u16(&pkt, MODBUS_TCP_REUSE_TID_BITS, 16 - MODBUS_TCP_REUSE_TID_BITS);
    uint16_t tid = _unmap_tid(state, mapid);
    /* Restore TID saved in map */
    bitstring_push_u16(&pkt, tid, 16);
    #else
    UNUSED(state);
    UNUSED(pkt);
    #endif
    eval_timer_measure_mod("end verified parse");
}

parser_module_t modbus_tcp_parser = {
    modbus_tcp_create,
    modbus_tcp_destroy,
    modbus_tcp_parse,
    modbus_tcp_embed,
    modbus_tcp_extract,
    modbus_tcp_restore,
    modbus_tcp_verified
};
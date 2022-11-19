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
 * Parser that accepts any buffer as packet
 * and overwrites the first bytes with up to 128 MAC bits.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 03.09.2021
 */

#include "../repel_modules.h"
#include "../repel_log.h"

#include <string.h>

#include "platform.h"
#include "../bitstring.h"

/**********************************************************
 *            Parameters to configure parser              *
 **********************************************************/

#define MAX_MAC_BITS    256
#define MAX_MAC_BYTES   ceil_bits_to_bytes(256)

/* create functions currently do not accept no state */
uint8_t fake_state;

void* fake_create(bitcount_t* max_embed_bits) {
    *max_embed_bits = MAX_MAC_BITS;
    return &fake_state;
}

void fake_destroy(void* self) {
    UNUSED(self);
}

parse_result_t fake_parse(void* self, in_buffer_t packet, bufsize_t buflen, repel_mode_t mode) {
    UNUSED(self);
    UNUSED(packet);
    UNUSED(mode);

    parse_result_t res;
    res.packet_has_nonce = false;

    if(buflen * 8 < MAX_MAC_BITS) {
        res.embed_bits = buflen * 8;
    } else {
        res.embed_bits = MAX_MAC_BITS;
    }
    res.pktlen = buflen;
    return res;
}

void fake_embed(void* self, inout_buffer_t packet, bufsize_t pktlen, in_buffer_t macbuf) {
    pkt_from(packet);
    mac_from(macbuf);
    UNUSED(self);
    uint16_t bits;
    if(pktlen * 8 < MAX_MAC_BITS) {
        bits = pktlen * 8;
    } else {
        bits = MAX_MAC_BITS;
    }
    while(bits > 64) {
        bitstring_copy_u64(&pkt, &mac, 64);
        bits -= 64;
    }
    if(bits > 0) {
        bitstring_copy_u64(&pkt, &mac, bits);
    }
}

void fake_extract(void* self, inout_buffer_t packet, bufsize_t pktlen, out_buffer_t macbuf) {
    pkt_from(packet);
    mac_from(macbuf);
    UNUSED(self);
    uint16_t bits;
    if(pktlen * 8 < MAX_MAC_BITS) {
        bits = pktlen * 8;
    } else {
        bits = MAX_MAC_BITS;
    }
    while(bits > 64) {
        bitstring_copy_u64(&mac, &pkt, 64);
        bits -= 64;
    }
    if(bits > 0) {
        bitstring_copy_u64(&mac, &pkt, bits);
    }
}

void fake_restore(void* self, inout_buffer_t packet, bufsize_t pktlen, repel_mode_t mode) {
    UNUSED(self);
    UNUSED(mode);
    if(pktlen > MAX_MAC_BYTES) {
        pktlen = MAX_MAC_BYTES;
    }
    memset(packet, 0, pktlen);
}

parser_module_t fake_parser = {
    fake_create,
    fake_destroy,
    fake_parse,
    fake_embed,
    fake_extract,
    fake_restore,
    NULL
};
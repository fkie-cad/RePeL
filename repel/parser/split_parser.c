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
 * Parser that overwrites the first packet bytes with a MAC, which it splits
 * into a configurable number of parts. Between each and before the first MAC
 * portion, the parser skips one bit. Requires at least 32 byte long packets.
 * Used for performance evaluation.
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
#include "../eval_timer.h"

/**********************************************************
 *            Parameters to configure parser              *
 **********************************************************/

#define MAX_MAC_BITS    256
#define OFFSET_BITS     1

#if EVAL_PKTALIGN
/* 1 bit per byte */
#define MIN_PKT_LEN     MAX_MAC_BITS

#elif EVAL_MACALIGN
#define MIN_PKT_LEN     ceil_bits_to_bytes(MAX_MAC_BITS * (OFFSET_BITS+1))
/* Fake MAC long enough to align to allow aligning the bitstring to bytes */
uint8_t fmac[MAX_MAC_BITS];

#else
#define MIN_PKT_LEN     ceil_bits_to_bytes(MAX_MAC_BITS * (OFFSET_BITS+1))
#endif

/**
 * Number of MAC portions. Set between runs to change
 */
uint16_t split_parser_mac_splits = 0;

#define _ceil_div(a, b) (((a) + (b) - 1) / (b))

void _bstr_copy_multibyte(bitstring_t* dst, bitstring_t* src, bitcount_t numbits) {
    /* Using u8 instead of u64 as u64 loops over u8's anyway, so remove some hidden complexity here */
    while(numbits > 8) {
        bitstring_copy_u8(dst, src, 8);
        numbits -= 8;
    }
    if(numbits) {
        bitstring_copy_u8(dst, src, numbits);
    }
}

void _bstr_zero_multibyte(bitstring_t* dst, bitcount_t numbits) {
    while(numbits > 8) {
        bitstring_push_u8(dst, 0, 8);
        numbits -= 8;
    }
    if(numbits) {
        bitstring_push_u8(dst, 0, numbits);
    }
}

void _bstr_byte_align(bitstring_t* bstr) {
    bstr->data += !!(bstr->shift);
    bstr->shift = 0;
}

void* split_create(bitcount_t* max_embed_bits) {
    *max_embed_bits = MAX_MAC_BITS;
    #if EVAL_MACALIGN
    for(int i = 0; i < MAX_MAC_BITS; i++) {
        fmac[i] = random_rand();
    }
    #endif
    return &split_parser_mac_splits;
}

void split_destroy(void* self) {
    UNUSED(self);
}

parse_result_t split_parse(void* self, in_buffer_t packet, bufsize_t buflen, repel_mode_t mode) {
    eval_timer_measure_mod("begin parse");
    UNUSED(self);
    UNUSED(packet);
    UNUSED(mode);

    parse_fail_on_minlen(MIN_PKT_LEN, buflen);

    parse_result_t res;
    res.packet_has_nonce = false;
    res.embed_bits = MAX_MAC_BITS;
    res.pktlen = buflen;

    eval_timer_measure_mod("end parse");
    return res;
}

void split_embed(void* self, inout_buffer_t packet, bufsize_t pktlen, in_buffer_t macbuf) {
    eval_timer_measure_mod("begin embed");
    pkt_from(packet);
    #if EVAL_MACALIGN
    bitstring_t mac = bitstring_init((inout_buffer_t) fmac);
    #else
    mac_from(macbuf);
    #endif
    UNUSED(self);
    UNUSED(pktlen);

    bitcount_t const segment_len = MAX_MAC_BITS / (split_parser_mac_splits + 1);
    /* Bits yet to process */
    bitcount_t bits = MAX_MAC_BITS;

    uint16_t s = 0;
    while(s < split_parser_mac_splits) {
        #if EVAL_PKTALIGN
        _bstr_byte_align(&pkt);
        #elif EVAL_MACALIGN
        _bstr_byte_align(&mac);
        #else
        bitstring_skip(&pkt, OFFSET_BITS);
        #endif
        _bstr_copy_multibyte(&pkt, &mac, segment_len);
        s++;
        bits -= segment_len;
    }
    /* Rest as last segment */
    #if EVAL_PKTALIGN
    _bstr_byte_align(&pkt);
    #elif EVAL_MACALIGN
    _bstr_byte_align(&mac);
    #else
    bitstring_skip(&pkt, OFFSET_BITS);
    #endif
    _bstr_copy_multibyte(&pkt, &mac, bits);

    eval_timer_measure_mod("end embed");
}

void split_extract(void* self, inout_buffer_t packet, bufsize_t pktlen, out_buffer_t macbuf) {
    eval_timer_measure_mod("begin extract");
    pkt_from(packet);
    #if EVAL_MACALIGN
    bitstring_t mac = bitstring_init((inout_buffer_t) fmac);
    #else
    mac_from(macbuf);
    #endif
    UNUSED(self);
    UNUSED(pktlen);

    bitcount_t const segment_len = MAX_MAC_BITS / (split_parser_mac_splits + 1);
    /* Bits yet to process */
    bitcount_t bits = MAX_MAC_BITS;

    uint16_t s = 0;
    while(s < split_parser_mac_splits) {
        #if EVAL_PKTALIGN
        _bstr_byte_align(&pkt);
        #elif EVAL_MACALIGN
        _bstr_byte_align(&mac);
        #else
        bitstring_skip(&pkt, OFFSET_BITS);
        #endif
        _bstr_copy_multibyte(&mac, &pkt, segment_len);
        s++;
        bits -= segment_len;
    }
    /* Rest as last segment */
    #if EVAL_PKTALIGN
    _bstr_byte_align(&pkt);
    #elif EVAL_MACALIGN
    _bstr_byte_align(&mac);
    #else
    bitstring_skip(&pkt, OFFSET_BITS);
    #endif
    _bstr_copy_multibyte(&mac, &pkt, bits);

    eval_timer_measure_mod("end extract");
}

void split_restore(void* self, inout_buffer_t packet, bufsize_t pktlen, repel_mode_t mode) {
    eval_timer_measure_mod("begin restore");
    pkt_from(packet);
    UNUSED(self);
    UNUSED(pktlen);
    UNUSED(mode);
    bitcount_t const segment_len = MAX_MAC_BITS / (split_parser_mac_splits + 1);
    /* Bits yet to process */
    bitcount_t bits = MAX_MAC_BITS;

    uint16_t s = 0;
    while(s < split_parser_mac_splits) {
        #if EVAL_PKTALIGN
        _bstr_byte_align(&pkt);
        #else
        bitstring_skip(&pkt, OFFSET_BITS);
        #endif

        _bstr_zero_multibyte(&pkt, segment_len);
        s++;
        bits -= segment_len;
    }
    /* Rest as last segment */
    #if EVAL_PKTALIGN
    _bstr_byte_align(&pkt);
    #else
    bitstring_skip(&pkt, OFFSET_BITS);
    #endif
    _bstr_zero_multibyte(&pkt, bits);

    eval_timer_measure_mod("end restore");
}

parser_module_t split_parser = {
    split_create,
    split_destroy,
    split_parse,
    split_embed,
    split_extract,
    split_restore,
    NULL
};

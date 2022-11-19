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
 * Implementation of truncated MACs.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 24.08.2021
 */

#include "../repel_modules.h"

#include <string.h>

#include "tinydtls.h"
#include "dtls-hmac.h"

#include "platform.h"
#include "../eval_timer.h"

#if REPEL_USE_HW_ACCEL
#include "dev/sha256.h"
#endif

#define HMAC_KEY_SIZE   16

#define HMAC_KEYSLOT_SEND   0
#define HMAC_KEYSLOT_RECV   1

struct HMacData {
    dtls_hmac_context_t ctx;
    /**
     * Keys in send and receive directions
     */
    uint8_t keys[2][HMAC_KEY_SIZE];
    /**
     * May be larger, depends on hmac_create
     */
    uint8_t buffer[DTLS_HMAC_DIGEST_SIZE];
};

void* hmac_create(bufsize_t maclen) {
    struct HMacData* data;
    unsigned int datalen = sizeof(struct HMacData);

    if(maclen < DTLS_HMAC_DIGEST_SIZE) {
        maclen = DTLS_HMAC_DIGEST_SIZE;
    }
    /* Expand data.buffer for parsers that embed a large number of bits */
    datalen += maclen - DTLS_HMAC_DIGEST_SIZE;

    data = (struct HMacData*) mem_alloc(datalen);
    if(!data) {
        return NULL;
    }

    memset(data->keys, 0, sizeof(data->keys));

    #if REPEL_USE_HW_ACCEL
    crypto_init();
    #endif
    return data;
}

void hmac_destroy(void* self) {
    #if REPEL_USE_HW_ACCEL
    crypto_disable();
    #endif
    mem_free(self);
}

out_buffer_t hmac_sign(void* self, in_buffer_t packet, bufsize_t pktlen,
    bitcount_t macbits, bitcount_t extrabits, noncebytes_t const* noncebytes) {

    eval_timer_measure_mod("begin mac");

    struct HMacData* data = (struct HMacData*) self;
    bufsize_t const bytes = ceil_bits_to_bytes(macbits + extrabits);
    memset(data->buffer, 0, bytes);

    eval_timer_measure_mod("begin sha");

    /* Put SHA256 hw acceleration in TinyDTLS "dtls-hmac.h" define REPEL_USE_HW_ACCEL to use */
    dtls_hmac_init(&data->ctx, data->keys[HMAC_KEYSLOT_SEND], HMAC_KEY_SIZE);
    dtls_hmac_update(&data->ctx, packet, pktlen);
    if(noncebytes) {
        dtls_hmac_update(&data->ctx, noncebytes->b, sizeof(noncebytes_t));
    }
    dtls_hmac_finalize(&data->ctx, data->buffer);

    eval_timer_measure_mod("end sha");

    eval_timer_measure_mod("end mac");
    /* Automatic truncation by library core */
    return data->buffer;
}

int16_t hmac_verify(void* self,  in_buffer_t packet, bufsize_t pktlen,
    in_buffer_t mac, bitcount_t bits, noncebytes_t const* noncebytes) {

    eval_timer_measure_mod("begin mac");

    struct HMacData* data = (struct HMacData*) self;
    memset(data->buffer, 0, ceil_bits_to_bytes(bits));

    /* Compute MAC of packet */
    eval_timer_measure_mod("begin sha");

    dtls_hmac_init(&data->ctx, data->keys[HMAC_KEYSLOT_RECV], HMAC_KEY_SIZE);
    dtls_hmac_update(&data->ctx, packet, pktlen);
    if(noncebytes) {
        dtls_hmac_update(&data->ctx, noncebytes->b, sizeof(noncebytes_t));
    }
    dtls_hmac_finalize(&data->ctx, data->buffer);

    eval_timer_measure_mod("end sha");

    /* Compare with extracted MAC; Special treatment for last bits */
    bufsize_t const fullbytes = bits / 8;
    bufsize_t const oddbits = bits % 8;

    if(memcmp(mac, data->buffer, fullbytes) == 0) {
        if(oddbits > 0) {
            uint8_t mrest = mac[fullbytes];
            uint8_t brest = data->buffer[fullbytes];
            uint8_t mask = 0xff >> oddbits;

            /* Check whether MSBs (which contain MAC bits) differ */
            if((mrest | mask) != (brest | mask)) {
                eval_timer_measure_mod("end mac");
                return -bits;
            }
        }
        eval_timer_measure_mod("end mac");
        return bits;
    } else {
        eval_timer_measure_mod("end mac");
        return -bits;
    }
}

void hmac_set_keys(void* self, void const* keys) {
    struct HMacData* data = (struct HMacData*) self;
    if(keys) {
        /* Assume the caller knows the key format */
        memcpy(data->keys, keys, sizeof(data->keys));
    }
}

mac_module_t hmac_module = {
    &hmac_create,
    &hmac_destroy,
    &hmac_sign,
    &hmac_verify,
    &hmac_set_keys
};
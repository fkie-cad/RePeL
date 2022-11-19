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
 * Implementation of a test MAC module that fills all MAC bits with ones.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 26.08.2021
 */

#include "../repel_modules.h"

#include "platform.h"
#include <string.h>

void* fakemac_create(bufsize_t maclen) {
    return mem_alloc(maclen);
}

void fakemac_destroy(void* self) {
    mem_free(self);
}

out_buffer_t fakemac_sign(void* self, in_buffer_t packet, bufsize_t pktlen,
    bitcount_t macbits, bitcount_t extrabits, noncebytes_t const* noncebytes) {

    UNUSED(packet);
    UNUSED(pktlen);
    UNUSED(noncebytes);

    inout_buffer_t buf = (inout_buffer_t) self;
    memset(buf, 0xff, ceil_bits_to_bytes(macbits + extrabits));
    return buf;
}

int16_t fakemac_verify(void* self,  in_buffer_t packet, bufsize_t pktlen,
    in_buffer_t mac, bitcount_t bits, noncebytes_t const* noncebytes) {

    UNUSED(self);
    UNUSED(packet);
    UNUSED(pktlen);
    UNUSED(noncebytes);

    bufsize_t const fullbytes = bits / 8;
    bufsize_t const oddbits = bits % 8;
    for(unsigned int i = 0; i < fullbytes; i++) {
        if(mac[i] != 0xff) {
            return -bits;
        }
    }
    if(oddbits > 0) {
        uint8_t mask = 0xff >> oddbits;
        if(mac[fullbytes] | (mask != 0xff)) {
            return -bits;
        }
    }
    return bits;
}

void fakemac_set_keys(void* self, void const* keys) {
    UNUSED(self);
    UNUSED(keys);
}

mac_module_t fakemac_module = {
    &fakemac_create,
    &fakemac_destroy,
    &fakemac_sign,
    &fakemac_verify,
    &fakemac_set_keys
};
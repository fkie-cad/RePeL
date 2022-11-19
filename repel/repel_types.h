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
 * Public type definitions for the Retrotfittable Protection Library (RePeL).
 * Using named types instead of C standard types allows later adjustment of ranges and type sizes.
 * This can be especially interesting for nonce_t, where 32 bit might suffice.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 23.08.2021
 */

#ifndef REPEL_TYPES_H_
#define REPEL_TYPES_H_

#include <stdint.h>

typedef struct MacModule const mac_module_t;
typedef struct ParserModule const parser_module_t;

/* Number used once */
typedef uint64_t nonce_t;
typedef union NonceBytes noncebytes_t;
union NonceBytes {
    uint8_t b[sizeof(nonce_t)];
};

static inline noncebytes_t netendian_nonce(nonce_t nonce) {
    noncebytes_t out;
    for(uint8_t i = 0; i < sizeof(nonce_t); i++) {
        out.b[i] = (uint8_t) (nonce >> ((sizeof(nonce_t)-i-1)*8));
    }
    return out;
}

#define NONCE_MASK (~((nonce_t) 0))
#define NONCE_MAX UINT64_MAX


typedef uint8_t const* in_buffer_t;
typedef uint8_t* out_buffer_t;
typedef uint8_t* inout_buffer_t;

typedef uint16_t bufsize_t;

/* 8192 bytes maximum which is still enough for our purposes */
typedef uint16_t bitcount_t;

#define ceil_bits_to_bytes(b)   (((b) + 7) / 8)

#define UNUSED(v)   ((void) (v))

#define POW2(E)     (1 << (E))

/**
 * val - res
 * 0   - 0
 * 1   - 1
 * 2   - 2
 * 3   - 2
 * 4   - 3
 * 5   - 3
 * 6   - 3
 * 7   - 3
 * 8   - 4
 * 9   - 4
 * ...
 */
static inline uint8_t bitcount(uint16_t val) {
    uint8_t l = 0;

    while(val) {
        val >>= 1;
        l++;
    }
    return l;
}

#endif
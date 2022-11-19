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
 * Type bitstring_t implementation that allows (de)compose bitfields to and from
 * byte arrays. These bitfields do not have to be byte aligned.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 28.05.2021
 */

#ifndef BITSTRING_H_
#define BITSTRING_H_

#include <stdint.h>

/**
 * Marks position of a single bit in a byte array.
 * This position can be moved forward via the functions
 * below (pop, push, skip, peek) while modifying the
 * underlying bits.
 */
typedef struct BitString bitstring_t;
struct BitString {
    uint8_t* data;
    /* From 0 to 7  */
    uint8_t shift;
};

bitstring_t bitstring_init(void* from);

void bitstring_skip(bitstring_t* string, unsigned int const bits);

void bitstring_rewind(bitstring_t* string, unsigned int const bits);


/**
 * \param bits Number of bits to pop
 * \return Consumed bits in the least significant bits of the return value (MSBs are zero)
 */
uint8_t bitstring_pop_u8(bitstring_t*, uint8_t const bits);

uint16_t bitstring_pop_u16(bitstring_t*, uint8_t const bits);

uint32_t bitstring_pop_u32(bitstring_t*, uint8_t const bits);

uint64_t bitstring_pop_u64(bitstring_t*, uint8_t const bits);

/**
 * \param bits Number of bits to return
 * \return Peeked bits in the least significant bits of the return value (MSBs are zero)
 */
uint8_t bitstring_peek_u8 (bitstring_t* string, unsigned int const offset, uint8_t const bits);

uint16_t bitstring_peek_u16 (bitstring_t* string, unsigned int const offset, uint8_t const bits);

uint32_t bitstring_peek_u32 (bitstring_t* string, unsigned int const offset, uint8_t const bits);

uint64_t bitstring_peek_u64 (bitstring_t* string, unsigned int const offset, uint8_t const bits);

/**
 * \param bits Number of bits to embed in stream
 */
void bitstring_push_u8 (bitstring_t* string, uint8_t val, uint8_t const bits);

void bitstring_push_u16 (bitstring_t* string, uint16_t val, uint8_t const bits);

void bitstring_push_u32 (bitstring_t* string, uint32_t val, uint8_t const bits);

void bitstring_push_u64 (bitstring_t* string, uint64_t val, uint8_t const bits);

static inline void bitstring_copy_u8(bitstring_t* dest, bitstring_t* src, uint8_t const bits) {
    uint8_t extract = bitstring_pop_u8(src, bits);
    bitstring_push_u8(dest, extract, bits);
}

static inline void bitstring_copy_u16(bitstring_t* dest, bitstring_t* src, uint8_t const bits) {
    uint16_t extract = bitstring_pop_u16(src, bits);
    bitstring_push_u16(dest, extract, bits);
}

static inline void bitstring_copy_u32(bitstring_t* dest, bitstring_t* src, uint8_t const bits) {
    uint32_t extract = bitstring_pop_u32(src, bits);
    bitstring_push_u32(dest, extract, bits);
}

static inline void bitstring_copy_u64(bitstring_t* dest, bitstring_t* src, uint8_t const bits) {
    uint64_t extract = bitstring_pop_u64(src, bits);
    bitstring_push_u64(dest, extract, bits);
}

#endif
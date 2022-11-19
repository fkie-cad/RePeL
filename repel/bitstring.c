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

#include "bitstring.h"

bitstring_t bitstring_init(void* from) {
    bitstring_t bstr;
    bstr.data = (uint8_t*) from;
    bstr.shift = 0;
    return bstr;
}

void bitstring_skip(bitstring_t* string, unsigned int const bits) { \
    unsigned int const offset = string->shift + bits;
    string->data += offset / 8;
    string->shift = (uint8_t) (offset % 8);
}

void bitstring_rewind(bitstring_t* string, unsigned int const bits) { \
    string->data -= bits / 8;
    string->shift -= bits % 8;
    if(string->shift >= 8) { /* Overflow */
        string->data--;
        string->shift %= 8;
    }
}

/**
 * @param bits Number of bits to pop
 * @return Consumed bits in the least significant bits of the return value (MSBs are zero)
 */
uint8_t bitstring_pop_u8(bitstring_t* string, uint8_t const bits) {
    uint8_t* const dt = string->data;
    uint8_t const shft = string->shift;

    uint8_t val = *dt << shft;
    if(shft > 8 - bits) {
        val |= *(dt + 1) >> (8 - shft);
    }
    if(shft >= 8 - bits) {
        string->data += 1;
    }
    string->shift = (shft + bits) % 8;
    return val >> (8 - bits);
}

uint16_t bitstring_pop_u16(bitstring_t* string, uint8_t const bits) {
    uint8_t _bits = bits - (bits % 8);
    uint16_t val = bitstring_pop_u8(string, bits % 8);
    while(_bits) {
        val = (val << 8) | bitstring_pop_u8(string, 8);
        _bits -= 8;
    }
    return val;
}

uint32_t bitstring_pop_u32(bitstring_t* string, uint8_t const bits) {
    uint8_t _bits = bits - (bits % 8);
    uint32_t val = bitstring_pop_u8(string, bits % 8);
    while(_bits) {
        val = (val << 8) | bitstring_pop_u8(string, 8);
        _bits -= 8;
    }
    return val;
}

uint64_t bitstring_pop_u64(bitstring_t* string, uint8_t const bits) {
    uint8_t _bits = bits - (bits % 8);
    uint64_t val = bitstring_pop_u8(string, bits % 8);
    while(_bits) {
        val = (val << 8) | bitstring_pop_u8(string, 8);
        _bits -= 8;
    }
    return val;
}

uint8_t bitstring_peek_u8(bitstring_t* string, unsigned int const offset, uint8_t const bits) {
    uint8_t* const dt = string->data + ((string->shift + offset) / 8);
    uint8_t const shft = (string->shift + offset) % 8;

    uint8_t val = *dt << shft;
    if(shft > 8 - bits) {
        val |= *(dt + 1) >> (8 - shft);
    }
    return val >> (8 - bits);
}

uint16_t bitstring_peek_u16(bitstring_t* string, unsigned int const offset, uint8_t const bits) {
    unsigned int _off = offset + (bits % 8);
    uint16_t val = bitstring_peek_u8(string, offset, bits % 8);

    while(_off < offset + bits) {
        val = (val << 8) | bitstring_peek_u8(string, _off, 8);
        _off += 8;
    }
    return val;
}

uint32_t bitstring_peek_u32(bitstring_t* string, unsigned int const offset, uint8_t const bits) {
    unsigned int _off = offset + (bits % 8);
    uint32_t val = bitstring_peek_u8(string, offset, bits % 8);

    while(_off < offset + bits) {
        val = (val << 8) | bitstring_peek_u8(string, _off, 8);
        _off += 8;
    }
    return val;
}

uint64_t bitstring_peek_u64(bitstring_t* string, unsigned int const offset, uint8_t const bits) {
    unsigned int _off = offset + (bits % 8);
    uint64_t val = bitstring_peek_u8(string, offset, bits % 8);

    while(_off < offset + bits) {
        val = (val << 8) | bitstring_peek_u8(string, _off, 8);
        _off += 8;
    }
    return val;
}

void bitstring_push_u8(bitstring_t* string, uint8_t val, uint8_t const bits) {
    uint8_t* const dt = string->data;
    uint8_t const shft = string->shift;
    uint8_t const mask = 0xff << (8 - bits);
    val <<= 8 - bits;

    /* Replace (mask and then add) bits in upper byte */
    *dt &= ~(mask >> shft);
    *dt |= val >> shft;

    /* Replace bits in lower byte if applicable */
    if(shft > 8 - bits) {
        *(dt + 1) &= ~(mask << (8 - shft));
        *(dt + 1) |= val << (8 - shft);
    }
    if(shft >= 8 - bits) {
        string->data += 1;
    }
    string->shift = (shft + bits) % 8;
}

void bitstring_push_u16(bitstring_t* string, uint16_t val, uint8_t const bits) {
    if(bits > 8) {
        bitstring_push_u8(string, (uint8_t) (val >> 8), bits - 8);
        bitstring_push_u8(string, (uint8_t) val, 8);
    } else {
        bitstring_push_u8(string, (uint8_t) val, bits);
    }
}

void bitstring_push_u32(bitstring_t* string, uint32_t val, uint8_t const bits) {
    uint8_t octs = bits / 8;

    bitstring_push_u8(string, (uint8_t) (val >> (8*octs)), bits % 8);
    while(octs > 0) {
        octs -= 1;
        bitstring_push_u8(string, (uint8_t) (val >> (8*octs)), 8);
    }
}

void bitstring_push_u64(bitstring_t* string, uint64_t val, uint8_t const bits) {
    uint8_t octs = bits / 8;

    bitstring_push_u8(string, (uint8_t) (val >> (8*octs)), bits % 8);
    while(octs > 0) {
        octs -= 1;
        bitstring_push_u8(string, (uint8_t) (val >> (8*octs)), 8);
    }
}
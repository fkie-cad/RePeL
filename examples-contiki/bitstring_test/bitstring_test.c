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
 * Program to test the correctness of RePeL's bitstring_t type
 * that allows (de)compose bitfields to and from byte arrays / packets.
 *
 * \author
 * Nils Rothaug
 */

#include "contiki.h"
#include "process.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h> /* For printf() */

#include "repel/bitstring.h"


#define ifn0(COMMENT, EXPR) { unsigned int tmp = EXPR; if(tmp != 0) ERRx(COMMENT, tmp); }
#define ifneq(CMT1, E1, CMT2, E2) { unsigned int tmp1 = E1, tmp2 = E2; if(tmp1 != tmp2) ERRxx(CMT1, tmp1, CMT2, tmp2); }
#define ERRx(COMMENT, X) { printf(COMMENT " %#x\n", (unsigned int) X); PROCESS_EXIT(); }
#define ERRxx(CMT1, X, CMT2, Y)  { printf(CMT1 " %#x " CMT2 " %#x\n", (unsigned int) X, (unsigned int) Y); PROCESS_EXIT(); }

// print bits
static void pbits(uint8_t byte) {
    char str[9];

    char* out = str + 8;
    *out = '\0';
    while(out > str) {
        --out;
        *out = (byte & 1)? '1' : '0';
        byte >>= 1;
    }

    printf("%s ", str);
}

PROCESS(bitstring_test, "BitString Test Process");
AUTOSTART_PROCESSES(&bitstring_test);

PROCESS_THREAD(bitstring_test, ev, data) {

    static uint8_t array[256];
    static bitstring_t bset = { array, 0 };
    static bitstring_t bcheck = { array, 0 };
    const uint8_t num8 = 0xff;
    const uint16_t num16 = 0xffff;
    const uint32_t num32 = 0xffffffff;
    static unsigned int i, mask = 1;

PROCESS_BEGIN();

    printf("Begin BitString test\n");
    memset(array, 0, sizeof(array));

    printf("Test u8:\n");
    for(i = 1, mask = 1; i <= 8; i++, mask = (mask << 1) | 1) {
        printf("skip; push %d bit(s): ", i);
        bitstring_skip(&bset, i);
        bitstring_push_u8(&bset, num8, i);

        pbits(array[0]);
        pbits(array[1]);
        pbits(array[2]);
        pbits(array[3]);
        pbits(array[4]);
        pbits(array[5]);
        pbits(array[6]);
        pbits(array[7]);
        pbits(array[8]);

        ifn0("ERROR: skipped bits, got: ", bitstring_pop_u8(&bcheck, i));
        ifneq("ERROR: got", bitstring_pop_u8(&bcheck, i), "instead of", num8 & mask);

        printf("OK @%d+%d\n", (int) (bset.data - array), (int) bset.shift);
    }

    printf("\nTest u16:\n");
    // Keep mask as it is
    for(i = 9; i <= 16; i++, mask = (mask << 1) | 1) {
        printf("skip; push %d bit(s): ", i);
        bitstring_skip(&bset, i);
        bitstring_push_u16(&bset, num16, i);

        pbits(array[9]);
        pbits(array[10]);
        pbits(array[11]);
        pbits(array[12]);
        pbits(array[13]);
        pbits(array[14]);
        pbits(array[15]);
        pbits(array[16]);
        pbits(array[17]);

        ifn0("ERROR: skipped bits, got: ", bitstring_pop_u16(&bcheck, i));
        ifneq("ERROR: got", bitstring_pop_u16(&bcheck, i), "instead of", num16 & mask);

        printf("OK @%d+%d\n", (int) (bset.data - array), (int) bset.shift);
    }

    printf("\nTest u32:\n");
    // Keep mask as it is
    for(i = 17; i <= 32; i++, mask = (mask << 1) | 1) {
        printf("skip; push %d bit(s): ", i);
        bitstring_skip(&bset, i);
        bitstring_push_u32(&bset, num32, i);

        ifn0("ERROR: skipped bits, got: ", bitstring_pop_u32(&bcheck, i));
        ifneq("ERROR: got", bitstring_pop_u32(&bcheck, i), "instead of", num32 & mask);

        printf("OK @%d+%d\n", (int) (bset.data - array), (int) bset.shift);
    }

    printf("\nTest bit clearing:\n");
    memset(array, 0xff, sizeof(array));
    bset = bitstring_init(array);
    bcheck = bitstring_init(array);
    mask = 1;

    for(i = 1; i <= 32; i++, mask = (mask << 1) | 1) {
        printf("skip; push %d zero bit(s): ", i);
        bitstring_skip(&bset, i);
        bitstring_push_u32(&bset, 0, i);

        ifneq("ERROR: skipped bits, got", bitstring_peek_u32(&bcheck, 0, i), "instead of", 0xffffffff & mask);
        ifn0("ERROR: got", bitstring_peek_u32(&bcheck, i, i));

        printf("OK, resetting: ");

        bitstring_push_u32(&bcheck, 0xffffffff, i);
        bitstring_push_u32(&bcheck, 0xffffffff, i);

        bitstring_rewind(&bcheck, i);
        ifneq("ERROR: reset bits, got", bitstring_pop_u32(&bcheck, i), "instead of", 0xffffffff & mask);

        printf("OK @%d+%d\n", (int) (bset.data - array), (int) bset.shift);
    }

    printf("Done\n");

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

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
 * Test program to evaluate RePeL's performance depending on the
 * number of nonce (number used once) bits that are embedded in a packet.
 *
 * \author
 * Nils Rothaug
 */
#include "contiki.h"
#include "sys/log.h"

#include "process.h"

#include <string.h>

#include "random.h"

#include <repel/repel.h>
#include <repel/repel_log.h>
#include <services/rpl-border-router/rpl-border-router.h>

#define MAX_NONCE_BITS  64
#define RUNS_PER_LEN    10
/* Use 32 Byte pktlen so that last MAC bits are actually overwritten and the nonce is not used appended */
#define PKTLEN          32


/*---------------------------------------------------------------------------*/
PROCESS(pktlen_test, "Pktlen Test");
AUTOSTART_PROCESSES(&pktlen_test);
/*---------------------------------------------------------------------------*/

static void auth_cb(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result) {
    (void) cbdata;
    (void) packet;

    info("Embedded bits: %d.", (int) result.protection_level);
}

PROCESS_THREAD(pktlen_test, ev, data) {
    static uint8_t keys[2][16] = {
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 },
        { 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
            0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34 }
    };
    static uint8_t pktbuf[PKTLEN];
    static repel_connection_t repel_con;

    static uint16_t noncebits = 0, run;

PROCESS_BEGIN();
    /* Keep border router to wait for log collection script */
    PROCESS_WAIT_EVENT_UNTIL(ev == RPL_EVENT_CONNECTED);

    /* Let run be the number of embedded nonce bits */
    while(noncebits <= MAX_NONCE_BITS) {
        run = 0;

        repel_con = repel_create_connection(&fake_parser, &hmac_module, noncebits);
        repel_set_keys(repel_con, keys);

        while(run < RUNS_PER_LEN) {
            for(int i = 0; i < PKTLEN; i++) {
                /* Pseudo randomness, hardware generator and seed on zoul */
                pktbuf[i] = random_rand();
            }

            repel_embed(repel_con, pktbuf, PKTLEN);
            repel_authenticate(repel_con, pktbuf, PKTLEN, &auth_cb, &auth_cb, NULL);
            run++;

            /* Calm the watchdogs */
            PROCESS_PAUSE();
        }

        repel_destroy_connection(repel_con);
        noncebits++;
        eval_next_run();
    }

    info("Done. NONCE_BITS=%u, PKTLEN=%u, RUNS_PER_LEN=%u.",
        (unsigned int) MAX_NONCE_BITS,
        (unsigned int) PKTLEN,
        (unsigned int) RUNS_PER_LEN);

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

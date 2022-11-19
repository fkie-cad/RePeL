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
 *         Test performance of SHA2 hmac implementations in isolation
 * \author
 *         Nils Rothaug
 */
#include "contiki.h"
#include "sys/log.h"

#include "process.h"

#include <string.h>

#include <repel/repel.h>
#include <repel/repel_log.h>
#include <services/rpl-border-router/rpl-border-router.h>

#include "random.h"

#include "tinydtls.h"
#include "dtls-hmac.h"
#include <repel/eval_timer.h>
#include "tinydtls-support/dtls-support-conf.h"

#define MAX_DATA_LEN     512
#define RUNS_PER_LEN    10


/*---------------------------------------------------------------------------*/
PROCESS(hwsha2_test, "SHA2 hw test");
AUTOSTART_PROCESSES(&hwsha2_test);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(hwsha2_test, ev, data) {
    static uint8_t key[16] =  {
        0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52,
        0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A, 0x72, 0x34
    };
    static dtls_hmac_context_t ctx;
    static uint8_t buf[MAX_DATA_LEN];
    static uint8_t digests[2][DTLS_SHA256_DIGEST_LENGTH];

    static uint16_t len = 1;
    static uint16_t run = 0;

PROCESS_BEGIN();
    /* Keep border router to wait for log collection script */
    PROCESS_WAIT_EVENT_UNTIL(ev == RPL_EVENT_CONNECTED);

    crypto_init();

    while(len <= MAX_DATA_LEN) {
        run = 0;
        while(run < RUNS_PER_LEN) {
            for(int i = 0; i < len; i++) {
                /* Pseudo randomness, hardware generator and seed on zoul */
                buf[i] = random_rand();
            }

            /* Sign using hw sha2 */
            set_tinydtls_use_hwsha2(true);
            eval_timer_start();
            dtls_hmac_init(&ctx, key, 16);
            eval_timer_measure_mod("inited");
            dtls_hmac_update(&ctx, buf, len);
            eval_timer_measure_mod("updated");
            dtls_hmac_finalize(&ctx, digests[0]);
            eval_timer_measure_mod("finalized");
            eval_timer_print("hw sha2", len);

            /* sw sha2 */
            set_tinydtls_use_hwsha2(false);
            eval_timer_start();
            dtls_hmac_init(&ctx, key, 16);
            eval_timer_measure_mod("inited");
            dtls_hmac_update(&ctx, buf, len);
            eval_timer_measure_mod("updated");
            dtls_hmac_finalize(&ctx, digests[1]);
            eval_timer_measure_mod("finalized");
            eval_timer_print("sw sha2", len);

            if(memcmp(digests[0], digests[1], DTLS_SHA256_DIGEST_LENGTH)) {
                error("SHA2 mismatch");
            }
            run++;

            /* Calm the watchdogs */
            PROCESS_PAUSE();
        }
        len++;
    }

    crypto_disable();
    info("Done. MAX_DATA_LEN=%u, RUNS_PER_LEN=%u.",
        (unsigned int) MAX_DATA_LEN,
        (unsigned int) RUNS_PER_LEN);

PROCESS_END();
}
/*---------------------------------------------------------------------------*/

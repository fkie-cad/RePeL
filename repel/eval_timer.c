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

#include "eval_timer.h"

#include <stdio.h>

#include "platform.h"

#if ENABLE_EVAL_TIMERS

bool _eval_timers_started = false;
uint32_t _eval_run = 0;

eval_timer_t _eval_global_timers;

unsigned long long _eval_timer_resolution_ns() {
    return 1000000000 / clk_ticks_per_second();
}

unsigned long long _eval_timer_usecs(platform_time_t t) {
    return ((unsigned long long) t) * 1000000 / clk_ticks_per_second();
}

void _eval_timer_print(char const* name, int32_t pktlen) {
    int i, len;
    unsigned long long res_ns = _eval_timer_resolution_ns();
    printf("{\n\t\"type\": \"timer\",\n\t\"label\": \"%s\",\n\t\"pktlen\": \"%li\",\n"
        "\t\"run\": \"%lu\",\n\t\"clockRes_us\": %llu.%03u,\n"
        "\t\"start\": %llu,\n\t\"stops\": [",
        name,                                           /* label */
        (signed long) pktlen,                           /* pktlen */
        (unsigned long) _eval_run,                      /* run */
        res_ns / 1000, (unsigned int) (res_ns % 1000),  /* clockRes #1, #2 */
        _eval_timer_usecs(_eval_global_timers.start)    /* start */
    );

    len = _eval_global_timers.index;
    for(i = 0; i < len; i++) {
        unsigned long long usecs = _eval_timer_usecs(_eval_global_timers.stops[i] - _eval_global_timers.start);
        if(i + 1 < len) {
            printf("\n\t\t{ \"%s\": %llu },", _eval_global_timers.labels[i], usecs);
        } else {
            printf("\n\t\t{ \"%s\": %llu }\n\t", _eval_global_timers.labels[i], usecs);
        }
    }

    printf("]\n},\n");
    _eval_timers_started = false;

}

#endif
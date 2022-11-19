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
 * Definitions for measuring series of timestamps
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 27.07.2021
 */

#ifndef EVAL_TIMER_H_
#define EVAL_TIMER_H_

#include <stdint.h>
#include <stdbool.h>

#include "platform.h"

/**
 * Whether timers are enabled
 */
#ifndef ENABLE_EVAL_TIMERS
#define ENABLE_EVAL_TIMERS true
#endif

/**
 * Maximum number of measurements that can be stored
 *
 * Currently, a maximum of up to 256 measurements is supported.
 */
#ifndef EVAL_TIMERS_MAX_STOPS
#define EVAL_TIMERS_MAX_STOPS 64
#endif

#if ENABLE_EVAL_TIMERS

/**
 * Holds a series of time measurements.
 * It is reset and initialized with eval_timer_start()
 * New measurements are added to an existing series with eval_timer_measure().
 */
typedef struct EvalTimer eval_timer_t;
struct EvalTimer {
    platform_time_t start;
    platform_time_t stops[EVAL_TIMERS_MAX_STOPS];
    char const* labels[EVAL_TIMERS_MAX_STOPS];
    uint8_t index;
};

extern bool _eval_timers_started;
extern uint32_t _eval_run;

extern eval_timer_t _eval_global_timers;

/**
 * Increase number of the current run which is printed with the measurements.
 */
#define eval_next_run() do { _eval_run++; } while(0)

/**
 * Start measuring
 */
#define eval_timer_start() do { \
    _eval_timers_started = true; \
    _eval_global_timers.index = 0; \
    _eval_global_timers.start = clk_ticks(); \
} while(0)

#define eval_timer_isrunning() _eval_timers_started

/**
 * Adds a new timestamp to series
 * XXX To minimize the influence of taking measurements on the resulting times,
 * No index checking is performed. Therefore, it must be ensured that no more
 * than EVAL_TIMER_MAX_STOPS measurements are taken between starting and stopping a timer.
 *
 * \param label Label of the measurement when printed in eval_timer_stop
 */
#define eval_timer_measure(label) do { \
    platform_time_t m = clk_ticks(); \
    uint8_t i = _eval_global_timers.index++; \
    _eval_global_timers.labels[i] = (label); \
    _eval_global_timers.stops[i] =  m; \
} while(0)

/**
 * Extra definition for module measurments.
 * Allows to easily switch of all intermediate measurings and
 * sanity check whether taking measurements skews them.
 */
#ifdef NO_MODULE_EVAL_TIMERS
#define eval_timer_measure_mod(lbl)
#else
#define eval_timer_measure_mod(lbl) eval_timer_measure(lbl)
#endif
/**
 * Prints measurements collected since eval_timer_start(...) in a format that resembles JSON.
 *
 * \param name String label of the measurement series
 */
#define eval_timer_print(name, pktlen)   _eval_timer_print(name, pktlen)
void _eval_timer_print(char const* name, int32_t pktlen);

#else

#define eval_next_run()
#define eval_timer_start()
#define eval_timer_isrunning() false
#define eval_timer_measure(label)
#define eval_timer_measure_mod(lbl) eval_timer_measure(lbl)
#define eval_timer_print(name, pktlen)

#endif

#endif
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
 * Interface to Linux specific helper routines, types, and macros for RePeL
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 06.06.2021
 */

#ifndef REPEL_CONTIKI_H_
#define REPEL_CONTIKI_H_

#include <stdint.h>
#include <stddef.h>

#include <stdlib.h>
#include <time.h>
#include <stdio.h>

typedef unsigned long platform_time_t;

#define mem_alloc(bytes) malloc(bytes)

#define mem_free(ptr) free(ptr)

static inline platform_time_t clk_ticks() {
    struct timespec time = {0, 0};
    clock_gettime(CLOCK_MONOTONIC_RAW, &time);

    /* 0.1us precision should be enough */
    return (time.tv_sec * 10000000) + (time.tv_nsec / 100);
}

#define clk_ticks_per_second()  10000000 /* 100ns precision */

#ifndef LOGTAG
#define LOGTAG "Repel"
#endif

enum PlatformLinuxLogLvl {
    LINUX_LOG_DEBUG,
    LINUX_LOG_INFO,
    LINUX_LOG_WARN,
    LINUX_LOG_ERROR,
    LINUX_LOG_NONE
};

extern enum PlatformLinuxLogLvl linux_log_level;

#define linux_set_log_level(lvl) linux_log_level = (lvl)

void _log_json(enum PlatformLinuxLogLvl lvl, char const* file, char const* format, ...);

void do_startup_logging();

void _log_pkt_json(char const* file, uint8_t const* pkt, uint16_t len);

void _log_pktdiff_json(char const* file, uint8_t const* pkt1, uint8_t const* pkt2, uint16_t len);

#define debug(...)  _log_json(LINUX_LOG_DEBUG, __FILE__, __VA_ARGS__)
#define info(...)   _log_json(LINUX_LOG_INFO, __FILE__, __VA_ARGS__)
#define warn(...)   _log_json(LINUX_LOG_WARN, __FILE__, __VA_ARGS__)
#define error(...)  _log_json(LINUX_LOG_ERROR, __FILE__, __VA_ARGS__)

#define log_packet(pkt, len) _log_pkt_json(__FILE__, pkt, len)
#define log_packet_diff(pkt1, pkt2, len) _log_pktdiff_json(__FILE__, pkt1, pkt2, len)

#endif
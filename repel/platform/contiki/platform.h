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
 * Interface to Contiki-NG specific helper routines, types, and macros for RePeL
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 06.06.2021
 */

#ifndef REPEL_CONTIKI_H_
#define REPEL_CONTIKI_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "lib/heapmem.h"
#include "sys/rtimer.h"
#include "sys/log.h"

typedef rtimer_clock_t platform_time_t;

void* mem_alloc(size_t bytes);
void mem_free(void* ptr);

#ifndef REPEL_ENABLE_LOGGING
#define REPEL_ENABLE_LOGGING true
#endif

#define clk_ticks()             RTIMER_NOW()
#define clk_ticks_per_second()  RTIMER_SECOND



#if REPEL_ENABLE_LOGGING

void _pre_log_json(int lvl, char const* file);
void _post_log_json();

void do_startup_logging();

void _log_pkt_json(char const* file, uint8_t const* pkt, uint16_t len);

void _log_pktdiff_json(char const* file, uint8_t const* pkt1, uint8_t const* pkt2, uint16_t len);

/*
 * Zoul does not support vprintf it seems
 */
#define debug(...)  do { _pre_log_json(LOG_LEVEL_DBG, __FILE__); printf(__VA_ARGS__); _post_log_json(); } while(0)
#define info(...)   do { _pre_log_json(LOG_LEVEL_INFO, __FILE__); printf(__VA_ARGS__); _post_log_json(); } while(0)
#define warn(...)   do { _pre_log_json(LOG_LEVEL_WARN, __FILE__); printf(__VA_ARGS__); _post_log_json(); } while(0)
#define error(...)  do { _pre_log_json(LOG_LEVEL_ERR, __FILE__); printf(__VA_ARGS__); _post_log_json(); } while(0)

#define log_packet(pkt, len) _log_pkt_json(__FILE__, pkt, len)
#define log_packet_diff(pkt1, pkt2, len) _log_pktdiff_json(__FILE__, pkt1, pkt2, len)

#else /* REPEL_ENABLE_LOGGING == false */

#define do_startup_logging()
#define debug(...)
#define info(...)
#define warn(...)
#define error(...)

#define log_packet(pkt, len)
#define log_packet_diff(pkt1, pkt2, len)

#endif

#endif
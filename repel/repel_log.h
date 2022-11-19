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
 * Public interface proxy to the library's platform independent logging mechanism.
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 23.08.2021
 */

#ifndef REPEL_LOG_H_
#define REPEL_LOG_H_

/* Proxy to platform specific logging functionality */
#include "platform.h"

#ifndef debug
#warning Repel logging macro 'debug' not defined!
#define debug(...)
#endif

#ifndef info
#warning Repel logging macro 'info' not defined!
#define info(...)
#endif

#ifndef warn
#warning Repel logging macro 'warn' not defined!
#define warn(...)
#endif

#ifndef error
#warning Repel logging macro 'error' not defined!
#define error(...)
#endif

#ifndef ENABLE_EVAL_TIMERS
#define ENABLE_EVAL_TIMERS true
#endif

#if ENABLE_EVAL_TIMERS
extern uint32_t _eval_run;
/**
 * Increase number of the current run which is printed with the measurements.
 */
#define eval_next_run() do { _eval_run++; } while(0)
#else
#define eval_next_run()
#endif

#endif
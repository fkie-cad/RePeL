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

#include "platform.h"

#include "../../eval_timer.h"
#include <stdio.h>
#include <stdarg.h>

enum PlatformLinuxLogLvl linux_log_level = LINUX_LOG_DEBUG;

void _log_json(enum PlatformLinuxLogLvl lvl, char const* file, char const* format, ...) {
    va_list(args);

    char const* lvlstr;
    switch(lvl) {
        case LINUX_LOG_INFO:
            lvlstr = "info";
            break;
        case LINUX_LOG_WARN:
            lvlstr = "warn";
            break;
        case LINUX_LOG_ERROR:
            lvlstr = "error";
            break;
        case LINUX_LOG_DEBUG:
            /* Fall through */
        default:
            lvlstr = "debug";
            break;
    }

    printf("{\n\t\"type\": \"log\",\n\t\"level\": \"%s\",\n\t\"file\": \"%s\",\n\t\"message\": \"", lvlstr, file);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}

void do_startup_logging() {
    /* Nothing here yet */
}

void _log_pkt_json(char const* file, uint8_t const* pkt, uint16_t len) {
    printf("{\n\t\"type\": \"packet\",\n\t\"file\": \"%s\",\n\t\"length\": \"%u\",\n\t\"hex\": \"", file, (unsigned int) len);
    while(len > 0) {
        printf("%x ", *pkt);
        pkt++;
        len--;
    }
    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}

void _log_pktdiff_json(char const* file, uint8_t const* pkt1, uint8_t const* pkt2, uint16_t len) {
    printf("{\n\t\"type\": \"packetdiff\",\n\t\"file\": \"%s\",\n\t\"length\": \"%u\",\n\t\"hex\": \"", file, (unsigned int) len);
    uint16_t diff = 0;
    while(len > 0) {
        if(*pkt1 == *pkt2) {
            printf("%x ", (unsigned int) *pkt1);
        } else {
            printf("[%x|%x] ", (unsigned int) *pkt1, (unsigned int) *pkt2);
            diff++;
        }
        pkt1++;
        pkt2++;
        len--;
    }
    printf("\",\n\t\"diffbytes\": \"%u", (unsigned int) diff);
    if(eval_timer_isrunning()) {
        printf("\",\n\t\"hint\": \"Logging while timers are running, results will be inaccurate.\"\n},\n");
    } else {
        printf("\"\n},\n");
    }
}
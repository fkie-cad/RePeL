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

#include "repel.h"
#include "repel_modules.h"

#include "platform.h"
#include "bitstring.h"
#include "eval_timer.h"

struct RepelConnection {
    parser_module_t* parser;
    mac_module_t* macalgo;
    void* parser_state;
    void* mac_state;
    struct {
        nonce_t send;
        nonce_t recv;
        uint8_t embed_bits;
    } nonce;
    /**
     * Buffer for parser to store extracted bits in.
     */
    uint8_t extrbuf[];
};

repel_connection_t repel_create_connection(parser_module_t* parser, mac_module_t* macalgo, uint8_t embed_nonce_bits) {

    do_startup_logging();

    bitcount_t max_embed_bits = 0;
    bufsize_t mac_bytes;
    void *pstate, *mstate;

    pstate = parser->create(&max_embed_bits);
    mac_bytes = ceil_bits_to_bytes(max_embed_bits);
    mstate = macalgo->create(mac_bytes);

    /* Add extract buffer length */
    repel_connection_t con = (repel_connection_t) mem_alloc(sizeof(struct RepelConnection) + mac_bytes);
    if(!con || !pstate || !mstate) {
        error("Out of memory: Creating connection failed");
        mem_free(pstate);
        mem_free(mstate);
        mem_free(con);
        return NULL;
    }

    con->parser = parser;
    con->parser_state = pstate;

    con->macalgo = macalgo;
    con->mac_state = mstate;

    con->nonce.send = 0;
    con->nonce.recv = 0;
    con->nonce.embed_bits = embed_nonce_bits;

    return con;
}

void repel_destroy_connection(repel_connection_t con) {
    if(con) {
        con->parser->destroy(con->parser_state);
        con->macalgo->destroy(con->mac_state);
        mem_free(con);
    }
}

void repel_set_keys(repel_connection_t con, void* keys) {
    con->macalgo->set_keys(con->mac_state, keys);
}

uint16_t repel_embed(repel_connection_t con, void* packet, uint16_t packet_size) {
    eval_timer_start();

    inout_buffer_t pktbytes = (inout_buffer_t) packet;

    parse_result_t pinfo = con->parser->parse(con->parser_state, pktbytes, packet_size, EMBED);
    /* Expecting well formatted packets as input => bail on length mismatch */
    if(pinfo.pktlen != packet_size || pinfo.embed_bits == 0) {
        eval_timer_measure("abort");
        eval_timer_print("embed", pinfo.pktlen);
        return 0;
    }

    con->parser->restore(con->parser_state, pktbytes, pinfo.pktlen, EMBED);

    inout_buffer_t mac;
    bitcount_t macbits = pinfo.embed_bits;
    bitcount_t noncebits;

    if(!pinfo.packet_has_nonce) {
        noncebits = con->nonce.embed_bits;

        if(pinfo.embed_bits <= noncebits) {
            eval_timer_measure("abort");
            eval_timer_print("embed", pinfo.pktlen);
            return 0; /* No MAC protection */
        }

        noncebytes_t netnonce = netendian_nonce(con->nonce.send);

        macbits -= noncebits;
        mac = con->macalgo->sign(con->mac_state, pktbytes, pinfo.pktlen, macbits, noncebits, &netnonce);

        /* Embed Nonce bits behind MAC in buffer */
        if(noncebits > 0) {
            bitstring_t macstr = bitstring_init(mac);
            bitstring_skip(&macstr, macbits);
            bitstring_push_u64(&macstr, con->nonce.send, noncebits); /* Handles endianness */
        }
        con->nonce.send++;
    } else {
        mac = con->macalgo->sign(con->mac_state, pktbytes, pinfo.pktlen, macbits, 0, NULL);
    }

    con->parser->embed(con->parser_state, pktbytes, pinfo.pktlen, mac);

    eval_timer_measure("done");
    eval_timer_print("embed", pinfo.pktlen);

    return macbits;
}

int32_t repel_authenticate(repel_connection_t con, void* packet, uint16_t buffer_size,
    auth_callback_fn_t* on_auth_success, auth_callback_fn_t* on_auth_failed, void* cbdata) {

    eval_timer_start();

    auth_result_t auth;
    inout_buffer_t pktbytes = (inout_buffer_t) packet;

    const parse_result_t pinfo = con->parser->parse(con->parser_state, pktbytes, buffer_size, AUTHENTICATE);

    if(pinfo.pktlen < 0) {
        eval_timer_measure("abort");
        eval_timer_print("authenticate", pinfo.pktlen);
        return pinfo.pktlen;
    }

    con->parser->extract(con->parser_state, pktbytes, pinfo.pktlen, con->extrbuf);
    con->parser->restore(con->parser_state, pktbytes, pinfo.pktlen, AUTHENTICATE);

    inout_buffer_t mac = con->extrbuf;
    bitcount_t macbits = pinfo.embed_bits;
    bitcount_t noncebits;
    int16_t protection;

    auth.nonce_embedded = !pinfo.packet_has_nonce;
    if(auth.nonce_embedded) {

        nonce_t nonce;
        noncebits = con->nonce.embed_bits;

        if(pinfo.embed_bits <= noncebits) {
            eval_timer_measure("abort");
            eval_timer_print("authenticate", pinfo.pktlen);
            return 0; /* No MAC protection */
        }

        /* Reconstruct  nonce from extracted bits */
        if(noncebits > 0) {
            macbits -= noncebits;

            bitstring_t macstr = bitstring_init(mac);
            bitstring_skip(&macstr, macbits);
            nonce = bitstring_pop_u64(&macstr, noncebits); /* Handles endianness */

            /* Determine upper bits from connection nonce  */
            const nonce_t recv = con->nonce.recv;
            nonce_t upper = recv & (NONCE_MASK << noncebits);

            nonce |= upper;
            if(nonce < recv) {
                nonce += 1 << noncebits;
            }
            if(nonce - recv < UINT16_MAX) {
                auth.packet_loss =  nonce - recv;
            } else {
                auth.packet_loss = UINT16_MAX;
            }
        } else {
            nonce = con->nonce.recv;
            auth.packet_loss = 0;
        }

        noncebytes_t netnonce = netendian_nonce(nonce);
        protection = con->macalgo->verify(con->mac_state, pktbytes, pinfo.pktlen, mac, macbits, &netnonce);
        if(protection > 0) {
            /* nonce accounts for lost packets, do not touch if packet not verified */
            con->nonce.recv = nonce + 1;
        }
    } else {
        protection = con->macalgo->verify(con->mac_state, pktbytes, pinfo.pktlen, mac, macbits, NULL);
    }

    if(protection > 0) {
        auth.protection_level = protection;
        /* This callback is optional */
        if(con->parser->verified) {
            con->parser->verified(con->parser_state, pktbytes, pinfo.pktlen);
        }
    } else {
        auth.protection_level = -protection;
    }

    eval_timer_measure("done");
    eval_timer_print("authenticate", pinfo.pktlen);

    /* Callbacks are not part of performance measurement */
    if(protection > 0) {
        if(on_auth_success) {
            on_auth_success(cbdata, pktbytes, pinfo.pktlen, auth);
        }
    } else {
        if(on_auth_failed) {
            on_auth_failed(cbdata, pktbytes, pinfo.pktlen, auth);
        }
    }

    return pinfo.pktlen;
}

int32_t _eval_parse_pkt_len(repel_connection_t con, void* packet, uint16_t packet_size) {
    inout_buffer_t pktbytes = (inout_buffer_t) packet;
    parse_result_t pinfo = con->parser->parse(con->parser_state, pktbytes, packet_size, EMBED);
    return pinfo.pktlen;
}
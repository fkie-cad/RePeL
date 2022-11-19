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
 * Parser and MAC module interfaces
 *
 * \author
 * Nils Rothaug
 *
 * \date
 * 23.08.2021
 */

#ifndef REPEL_MODULES_H_
#define REPEL_MODULES_H_

#include "repel_types.h"
#include <stdbool.h>

/**********************************************************
 *               Module base function types               *
 **********************************************************/

enum RepelMode {
    EMBED, AUTHENTICATE
};
typedef enum RepelMode repel_mode_t;

/**
 * Destroys Module instance data returned from a ..._create_fn_t implementation.
 */
typedef void module_destroy_fn_t(void* self);

/**********************************************************
 *                       MAC module                       *
 **********************************************************/

/**
 * Creates and returns a new MAC module instance.
 *
 * \param Maximum MAC length in bytes that the module must be able to calculate.
 * Implementations can, e.g., extend shorter MACs with 0 bytes.
 *
 * \return Module instance data.
 */
typedef void* mac_create_fn_t(bufsize_t maclen);

/**
 * Calculates the signature of a packet and optionally a nonce.
 * macbits + extrabits is never larger than the maximum MAC length
 * indicated at module creation.
 *
 * \return Buffer containing the packet signature and extra space at the end.
 *
 * \param self MAC module instance data.
 *
 * \param packet Packet to sign.
 *
 * \param pktlen Length of packet.
 *
 * \param macbits Desired MAC length.
 *
 * \param extrabits Length of extra space in returned buffer in bits.
 *
 * \param nonce Points to a Number used once to include in the signature or NULL when unused.
 * The nonce is already converted to network byte order.
 */
typedef out_buffer_t mac_sign_fn_t(void* self, in_buffer_t packet, bufsize_t pktlen,
    bitcount_t macbits, bitcount_t extrabits, noncebytes_t const* noncebytes);

/**
 * Verifies a received MAC.
 *
 * \return Protection level in bits when verifiable (usually copied from parameter 'bits'),
 * negative protection level when verification failed.
 *
 * \param self Optional instance data.
 *
 * \param recvmac MAC extracted from packet.
 *
 * \param bits Length of extracted MAC in bits.
 *
 * \param nonce Points to the Number used once included in the signature or NULL when unused.
 * The nonce is already converted to network byte order.
 */
typedef int16_t mac_verify_fn_t(void* self, in_buffer_t packet, bufsize_t pktlen,
    in_buffer_t mac, bitcount_t bits, noncebytes_t const* noncebytes);

/**
 * Sets key material for a connection.
 * The key(s) are opaque to the library, their format defined by the MAC module implementation and known by the application.
 * An implementation could, for example, expect one key for send and one for receive directions, or a single key.
 */
typedef void mac_set_keys_fn_t(void* self, void const* keys);

struct MacModule {
    mac_create_fn_t* const create;
    module_destroy_fn_t* const destroy;

    mac_sign_fn_t* const sign;
    mac_verify_fn_t* const verify;
    mac_set_keys_fn_t* const set_keys;
};

/**********************************************************
 *                     Parser module                      *
 **********************************************************/

typedef struct ParseResult parse_result_t;
struct ParseResult {
    /**
     * Length of the parsed packet in bytes if positive.
     * Minimum number of bytes missing at the packet end if negative.
     * Parsing error, when zero.
     */
    int32_t pktlen;

    /**
     * Number of bits that can be embedded in the parsed packet.
     */
    bitcount_t embed_bits;

    /**
     * Whether the parser determines the packet contains a nonce already.
     * This disables the libraries builtin nonce scheme.
     */
    bool packet_has_nonce;
};

/**
 * Creates and returns a new module instance.
 *
 * \return Module instance data.
 *
 * \param max_embed_bits Must be set by the parser to the maximum
 * number of bits the parser can embed in any packet.
 * Used to determine the buffer size supplied to embed.
 */
typedef void* parser_create_fn_t(bitcount_t* max_embed_bits);

/**
 * Parses a packet to determine its length and how many bits can be embedded in this packet.
 * Note that the parse function must ignore any regions where bits can be embedded as it must
 * parse both packets with and without embedded MAC.
 *
 * \return Zero length on persing (format) error,
 * negative length when bytes at the packet end are missing (length mismatch).
 * Must not be larger than max_embed_bits signalled at module creation.
 */
typedef parse_result_t parser_parse_fn_t(void* self, in_buffer_t packet, bufsize_t pktlen, repel_mode_t mode);

/**
 * Embeds MAC bits in a packet.
 *
 * \param mac Buffer that contains the MAC bits. The MAC length is determined by the parse function result.
 */
typedef void parser_embed_fn_t(void* self, inout_buffer_t packet, bufsize_t pktlen, in_buffer_t mac);

/**
 * Extracts the embedded MAC bits from the packet.
 *
 * \param mac buffer to store mac bits in. Guaranteed size is max_embed_bits from create function.
 */
typedef void parser_extract_fn_t(void* self, inout_buffer_t packet, bufsize_t pktlen, out_buffer_t mac);

/**
 * Restores a packet to a fully protocol conform and deterministic state.
 * This includes erasing the embedded MAC bits.
 * In particular, the resulting packet contents must not depend on whether a MAC was embedded previously.
 * This function is called in preparation to calculating a MAC for comparison.
 *
 * \param packet Packet to restore (modify)
 */
typedef void parser_restore_fn_t(void* self, inout_buffer_t packet, bufsize_t pktlen, repel_mode_t mode);

/**
 * Complements restore function and has a similar purpose.
 * Runs after (and only if) the packet was verified by the MAC module.
 * This function was necessary for the Modbus TCP parser to unmap the server
 * Transaction Identifier to the Transaction Id expected by the client.
 * This has to happen after MAC verification as the server does not know about
 * the TID mapping and calculates the MAC with mapped TID.
 * This function is optional and only used during authenticate.
 * The parser module may contain a NULL pointer instead.
 *
 * \param packet Packet to modify
 */
typedef void parser_verified_fn_t(void* self, inout_buffer_t packet, bufsize_t pktlen);

struct ParserModule {
    parser_create_fn_t* const create;
    module_destroy_fn_t* const destroy;

    parser_parse_fn_t* const parse;
    parser_embed_fn_t* const embed;
    parser_extract_fn_t* const extract;
    parser_restore_fn_t* const restore;
    parser_verified_fn_t* const verified;
};

/**********************************************************
 *                 Parser util functions                  *
 **********************************************************/

#define state_from(TYPE, param) TYPE* state = (TYPE*) param
/**
 * Defines bitstring_t pkt;
 * Discards const qualifier, caller must not use write-bitstring functions!
 */
#define pkt_from(pktbuf)        bitstring_t pkt = bitstring_init((inout_buffer_t) pktbuf)
/**
 * Defines bitstring_t mac;
 * Discards const qualifier, caller must not use write-bitstring functions!
 */
#define mac_from(macbuf)        bitstring_t mac = bitstring_init((inout_buffer_t) macbuf)

#define parse_fail_on_minlen(minlen, pktlen)    if(pktlen < minlen) { return (parse_result_t) { ((int32_t) pktlen) - ((int32_t) minlen), 0, false }; }

#endif
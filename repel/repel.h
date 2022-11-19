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
 * Public interface for the Retrofittable protection Library (RePeL).
 *
 * \author
 * Nils Rothaug
 */

#ifndef REPEL_H_
#define REPEL_H_

#include "repel_types.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct AuthenticateResult auth_result_t;
struct AuthenticateResult {
    /**
     * Bit count of embedded / extracted integrity protection information.
     */
    uint16_t protection_level;
    /**
     * Estimated number of packets that were lost between the current and the last verified packet.
     */
    uint16_t packet_loss;
    /**
     * Whether the library embedded a nonce in the packet.
     */
    bool nonce_embedded;
};

/**
 * Callback function type for repel_authenticate.
 *
 * \param cbdata Opaque callback data
 * \param packet The packet that was authenticated
 * \param packet_len The packet's length
 * \param result Various meta information, including the protection level.
 */
typedef void auth_callback_fn_t(void* cbdata, void* packet, uint16_t packet_len, auth_result_t result);

typedef struct RepelConnection* repel_connection_t;

/**
 * Create a new connection specific library instance that can be used to protect and authenticate packets.
 *
 * \param parser Parser module to use.
 * \param macalgo MAC module to use.
 * \param embed_nonce_bits The number of Nonce bits that are sent along with each packet
 * for nonce synchronization.
 * Note, that no nonce bits are embedded when the parser identifies a nonce is part
 * of the legacy protocol.
 */
repel_connection_t repel_create_connection(parser_module_t* parser, mac_module_t* macalgo, uint8_t embed_nonce_bits);

/**
 * Call to free connection state.
 */
void repel_destroy_connection(repel_connection_t con);

/**
 * Sets the session and MAC implementation specific key.
 * Passing a key which does match the expacted size and format
 * of the MAC implementation in use causes undefined behaviour.
 */
void repel_set_keys(repel_connection_t con, void* keys);

/**
 * Calculates and embeds the packet's MAC according to MAC implementation and parser configured in session.
 *
 * \param con Repel configuration that determines MAC and parser, as well as connection specific information.
 * \param packet Packet data that is parsed and modified by the parser.
 * \param packet_size Packet size.
 * \return Positive number of bits embedded in the packet. Zero on error.
 */
uint16_t repel_embed(repel_connection_t con, void* packet, uint16_t packet_size);

/**
 * Removes embedded MAC from packet and validates it.
 *
 * \return The positive packet length when a full packet was detected and one callback function called.
 * The negative lower bound of bytes missing for a full packet, if the parser detected an incomplete packet.
 * Zero on parsing error.
 *
 * \param con Repel configuration that determines MAC and parser, as well as connection specific information.
 * \param packet Packet data that is parsed and modified by the parser. It's length may not be known.
 * \param buffer_size Size of the buffer in which the packet resides.
 * \param on_auth_success Callback invoked on successfull packet authentication.
 * \param on_auth_failed Callback invoked when authentication of an otherwise valid packet failed.
 * \param cbdata opaque data relayed to either callback function.
 */
int32_t repel_authenticate(repel_connection_t con, void* packet, uint16_t buffer_size,
    auth_callback_fn_t* on_auth_success, auth_callback_fn_t* on_auth_failed, void* cbdata);

/**
 * Hacky function for eval: We send packets from TCP trace without knowing the app layer length.
 * Instead of parsing the length for each protocol, we ask the parser.
 * Requires the parser to not modify the module state in the parse function.
 *
 * \return Length if positive, error otherwise
 */
int32_t _eval_parse_pkt_len(repel_connection_t con, void* packet, uint16_t packet_size);

/**
 * SHA-256 truncated HMAC
 */
extern mac_module_t hmac_module;

/**
 * Test MAC module that does not provide integrity or replay protection.
 */
extern mac_module_t fakemac_module;

extern parser_module_t modbus_tcp_parser;

/**
 * Test parser module that overwrites the first packet bytes with MAC bits.
 */
extern parser_module_t fake_parser;

extern parser_module_t split_parser;
extern uint16_t split_parser_mac_splits;

#endif
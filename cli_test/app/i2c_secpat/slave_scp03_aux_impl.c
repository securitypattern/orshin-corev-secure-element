/*

Copyright (c) 2025, Security Pattern s.r.l. All rights reserved.
SPDX-License-Identifier: MIT

*/

#include "../include/slave_scp03APDU_def.h"

session_state_t session_state = UNINITIATED;

uint8_t static_key[STATIC_KEY_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t id_K[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t counter_K[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
uint8_t nonceH[NONCE_LEN];
uint8_t nonceSE[NONCE_LEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0a, 0x0b,
		0x03, 0x07, 0x0f, 0x01, 0x01, 0x01, 0xe, 0xd };

Xoodyak_Instance instance;

void scp03aux_command_dec(session_context_t *scp03SessCtxt,
		uint8_t *decCommandBuf, uint8_t *isTrueVerifyMAC) {
	uint8_t *commandBuf = scp03SessCtxt->rx_APDU_message; /* The encrypted and authenticated CAPDU. */
	uint16_t payload_len = scp03SessCtxt->rx_APDU_data_len; /* Payload length of the encrypted and authenticated CAPDU. */
	uint16_t dec_payload_len; /* Payload length of the decrypted CAPDU. */
	uint8_t tag_verif_res = -1; /* Result of Xoodyak tag verification. */
	uint8_t tag[16];

	if (session_state == UNINITIATED) {
		memcpy(nonceH, commandBuf + CAPDU_HEADER_LEN + payload_len - NONCE_LEN,
		NONCE_LEN); /* Extract nonceH from the CAPDU. */

		Xoodyak_Initialize(&instance, static_key, STATIC_KEY_LEN, id_K, 16,
				counter_K, 16);
		Xoodyak_Absorb(&instance, nonceH, NONCE_LEN);
		Xoodyak_Ratchet(&instance);
		Xoodyak_Absorb(&instance, commandBuf, CAPDU_HEADER_LEN);
		Xoodyak_Decrypt(&instance, commandBuf + CAPDU_HEADER_LEN,
				decCommandBuf + CAPDU_HEADER_LEN,
				(size_t) (payload_len - NONCE_LEN - AUTH_TAG_LEN));
		Xoodyak_Squeeze(&instance, tag, AUTH_TAG_LEN);
		if (memcmp(tag,
				commandBuf + CAPDU_HEADER_LEN
						+ payload_len- NONCE_LEN - AUTH_TAG_LEN, AUTH_TAG_LEN)
				!= 0) {
			memset(decCommandBuf + CAPDU_HEADER_LEN, 0,
					(size_t) (payload_len - NONCE_LEN));
			tag_verif_res = -1;
		} else {
			tag_verif_res = 0;
			dec_payload_len = payload_len - AUTH_TAG_LEN - NONCE_LEN;
		}
		session_state = HANDSHAKE;
	} else {
		Xoodyak_Absorb(&instance, commandBuf, CAPDU_HEADER_LEN);
		Xoodyak_Decrypt(&instance, commandBuf + CAPDU_HEADER_LEN,
				decCommandBuf + CAPDU_HEADER_LEN,
				(size_t) (payload_len - AUTH_TAG_LEN));
		Xoodyak_Squeeze(&instance, tag, AUTH_TAG_LEN);
		if (memcmp(tag,
				commandBuf + CAPDU_HEADER_LEN + payload_len - AUTH_TAG_LEN,
				AUTH_TAG_LEN) != 0) {
			memset(decCommandBuf + CAPDU_HEADER_LEN, 0, (size_t) payload_len);
			tag_verif_res = -1;
		} else {
			tag_verif_res = 0;
			dec_payload_len = payload_len - AUTH_TAG_LEN;
		}
	}

	memcpy(decCommandBuf, commandBuf, CAPDU_HEADER_LEN);
	decCommandBuf[iLC1CAPDU] = (uint8_t) (dec_payload_len >> 8);
	decCommandBuf[iLC2CAPDU] = (uint8_t) (dec_payload_len);

	if (tag_verif_res == 0) {
		*isTrueVerifyMAC = 1;
	} else {
		*isTrueVerifyMAC = 0;
	}
}

void scp03aux_response_enc(uint8_t *responseBuf) {
	uint16_t payload_len = (((uint16_t) responseBuf[iLC1RAPDU]) << 8)
			+ ((uint16_t) responseBuf[iLC2RAPDU]); /* Response payload length (excludes the SWs). */
	uint16_t enc_payload_len; /* Response payload length after encryption and authentication. */
	uint16_t temp;
	uint8_t SW1, SW2; /* RAPDU status words. */
	uint16_t iSW1 = RAPDU_HEADER_LEN + payload_len; /* Position within responseBuf of SW1. */
	uint16_t iSW2 = RAPDU_HEADER_LEN + payload_len + 1; /* Position within responseBuf of SW2. */

	SW1 = responseBuf[iSW1];
	SW2 = responseBuf[iSW2];

	if (session_state == HANDSHAKE) {
		temp = payload_len + AUTH_TAG_LEN + NONCE_LEN;
		responseBuf[iLC1RAPDU] = (uint8_t) (temp >> 8); /* Update LC field. */
		responseBuf[iLC2RAPDU] = (uint8_t) (temp); /* Update LC field. */

		Xoodyak_Absorb(&instance, responseBuf, RAPDU_HEADER_LEN); /* Absorb AD */
		Xoodyak_Absorb(&instance, responseBuf + iSW1, 1); /* Absorb AD */
		Xoodyak_Absorb(&instance, responseBuf + iSW2, 1); /* Absorb AD */
		Xoodyak_Absorb(&instance, nonceSE, NONCE_LEN); /* Absorb AD */
		Xoodyak_Encrypt(&instance, responseBuf + RAPDU_HEADER_LEN,
				responseBuf + RAPDU_HEADER_LEN, payload_len); /* Encrypt RAPDU payload. */
		Xoodyak_Squeeze(&instance, responseBuf + RAPDU_HEADER_LEN + payload_len,
				AUTH_TAG_LEN);
		enc_payload_len = payload_len + AUTH_TAG_LEN;

		memcpy(responseBuf + RAPDU_HEADER_LEN + enc_payload_len, nonceSE,
				NONCE_LEN); /* Append nonceSE to the RAPDU payload. */

		iSW1 = RAPDU_HEADER_LEN + enc_payload_len + NONCE_LEN;
		iSW2 = RAPDU_HEADER_LEN + enc_payload_len + NONCE_LEN + 1;
		responseBuf[iSW1] = SW1; /* Re-append SW1. */
		responseBuf[iSW2] = SW2; /* Re-append SW2. */

		session_state = ACTIVE;
	} else {
		temp = payload_len + AUTH_TAG_LEN;
		responseBuf[iLC1RAPDU] = (uint8_t) (temp >> 8); /* Update LC field. */
		responseBuf[iLC2RAPDU] = (uint8_t) (temp); /* Update LC field. */

		Xoodyak_Absorb(&instance, responseBuf, RAPDU_HEADER_LEN); /* Absorb AD */
		Xoodyak_Absorb(&instance, responseBuf + iSW1, 1); /* Absorb AD */
		Xoodyak_Absorb(&instance, responseBuf + iSW2, 1); /* Absorb AD */
		Xoodyak_Encrypt(&instance, responseBuf + RAPDU_HEADER_LEN,
				responseBuf + RAPDU_HEADER_LEN, payload_len); /* Encrypt RAPDU payload. */
		Xoodyak_Squeeze(&instance, responseBuf + RAPDU_HEADER_LEN + payload_len,
				AUTH_TAG_LEN);
		enc_payload_len = payload_len + AUTH_TAG_LEN;

		iSW1 = RAPDU_HEADER_LEN + enc_payload_len;
		iSW2 = RAPDU_HEADER_LEN + enc_payload_len + 1;
		responseBuf[iSW1] = SW1; /* Re-append SW1. */
		responseBuf[iSW2] = SW2; /* Re-append SW2. */
	}
}


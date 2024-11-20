/* Copyright (c) 2024 Joan Bushi

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

#include "../include/slave_scp03APDU_def.h"
#include "../include/slave_T1_def.h"
#include "../include/secpat_i2c.h"
#include <string.h>

session_context_t scp03_sess_ctxt; /* Session context data. */

void set_rec_APDU_message(uint8_t *ptrRecAPDU) {
	scp03_sess_ctxt.rx_APDU_data_len = ptrRecAPDU[iLC1CAPDU];
	scp03_sess_ctxt.rx_APDU_data_len <<= 8;
	scp03_sess_ctxt.rx_APDU_data_len |= ptrRecAPDU[iLC2CAPDU];
	memcpy(scp03_sess_ctxt.rx_APDU_message, ptrRecAPDU, CAPDU_HEADER_LEN + scp03_sess_ctxt.rx_APDU_data_len);
}

void scp03APDU_construct_resp_APDU_message(uint8_t *ptrAPDUCommand,
		uint8_t *ptrAPDUResponse, uint8_t *ptrAPDUResponseLen) {
	set_rec_APDU_message(ptrAPDUCommand);
	get_command_type(&scp03_sess_ctxt.rx_APDU_command_type);

	if ((scp03_sess_ctxt.rx_APDU_message[0] & 0x4) == 0) { /* You should add a condition to check whether the secure channel has been established */
		switch (scp03_sess_ctxt.rx_APDU_command_type) {
		case SELECT:
			break;
		default:
			break;
		}
	} else {
		prepare_response_APDU(ptrAPDUCommand, ptrAPDUResponse,
				ptrAPDUResponseLen);
	}
}

void prepare_response_APDU(uint8_t *ptrAPDUCommand, uint8_t *ptrAPDUResponse,
		uint8_t *ptrAPDUResponseLen) {
	uint8_t commandBuf[MAX_DATA_LEN]; /* The decrypted data received from the master. */
	uint8_t responseBuf[MAX_DATA_LEN]; /* The data to be sent to the master. */
	uint8_t SW1, SW2; /* SW bytes of the response. */
	uint16_t responseLen = 0; /* Length of the entire RAPDU to be sent to the master. */
	bool_t isTrue_verify_MAC; /* Is the calculated MAC the same as the received MAC? */

	hal_toggle_gpio((uint8_t) COMMAND_DECRYPT_AUTH_GPIO);
	scp03aux_command_dec(&scp03_sess_ctxt, commandBuf, &isTrue_verify_MAC);
	hal_toggle_gpio((uint8_t) COMMAND_DECRYPT_AUTH_GPIO);

	if (isTrue_verify_MAC) { /* Command processing OK. */
		switch (scp03_sess_ctxt.rx_APDU_command_type) {
		case ECHO:
			echo_response(responseBuf, &responseLen, commandBuf);
			break;
		default:
			break;
		}

		/*** BEGIN Add the SW bytes. ***/
		SW1 = 0x90;
		SW2 = 0x00;
		responseBuf[responseLen++] = SW1;
		responseBuf[responseLen++] = SW2;
		/*** END Add the SW bytes. ***/

		hal_toggle_gpio((uint8_t) RESP_ENCRYPT_MAC_GPIO);
		scp03aux_response_enc(responseBuf);
		hal_toggle_gpio((uint8_t) RESP_ENCRYPT_MAC_GPIO);

		responseLen = RAPDU_HEADER_LEN; /* RAPDU header length. */
		responseLen += (((uint16_t) responseBuf[iLC1RAPDU]) << 8)
				+ ((uint16_t) responseBuf[iLC2RAPDU]); /* RAPDU payload length. */
		responseLen += 2; /* RAPDU SWs field length. */

		memcpy(ptrAPDUResponse, responseBuf, responseLen);
		*ptrAPDUResponseLen = responseLen;
	} else { /* Command processing failed. */
		responseLen = 2; /* Set the response data length. */

		/*** BEGIN Add the SW bytes. ***/
		SW1 = 0x63;
		SW2 = 0x00;
		responseBuf[responseLen++] = SW1;
		responseBuf[responseLen++] = SW2;
		memcpy(ptrAPDUResponse, responseBuf, responseLen);
		*ptrAPDUResponseLen = responseLen;
		/*** END Add the SW bytes. ***/
	}
}

void echo_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen,
		uint8_t *ptrCommandDataDec) {
	uint16_t response_payload_len;
	response_payload_len = (((uint16_t) ptrCommandDataDec[iLC1CAPDU]) << 8)
			+ (((uint16_t) ptrCommandDataDec[iLC2CAPDU]));
	memcpy(ptrResponseData, ptrCommandDataDec, RAPDU_HEADER_LEN - 2); /* Copy the CLA and INS of the CAPDU. */
	memcpy(ptrResponseData + 2, ptrCommandDataDec + RAPDU_HEADER_LEN, 2); /* Copy the Lc field of the CAPDU. */
	memcpy(ptrResponseData + RAPDU_HEADER_LEN,
			ptrCommandDataDec + CAPDU_HEADER_LEN, response_payload_len);
	*ptrResponseDataLen = RAPDU_HEADER_LEN + response_payload_len;
}

void get_command_type(APDU_command_t *commandType) {
	uint8_t CLA, INS, P1, P2;

	CLA = scp03_sess_ctxt.rx_APDU_message[i_CLA];
	INS = scp03_sess_ctxt.rx_APDU_message[i_INS];
	P1 = scp03_sess_ctxt.rx_APDU_message[i_P1];
	P2 = scp03_sess_ctxt.rx_APDU_message[i_P2];

	if (CLA == 0x00 && INS == 0xa4) { /* SELECT */
		*commandType = SELECT;
	} else if (CLA == 0x84 && INS == 0x04 && P1 == 0x00 && P2 == 0x20) /* GET VERSION */
	{
		*commandType = GET_VERSION;
	} else if (CLA == 0x84 && INS == 0x04 && P1 == 0x00 && P2 == 0x27) /* GET VERSION */
	{
		*commandType = CHECK_OBJECT_EXISTS;
	} else if (CLA == 0x84 && INS == 0x01 && P1 == 0x61 && P2 == 0x00) { /* WRITE ECKEY */
		*commandType = WRITE_ECKEY;
	} else if (CLA == 0x84 && INS == 0x04 && P1 == 0x00 && P2 == 0x28) { /* DELETE SECURE OBJECT */
		*commandType = DELETE_SECURE_OBECT;
	} else if (CLA == 0x84 && INS == 0x02 && P1 == 0x00 && P2 == 0x00) {
		*commandType = READ_OBJECT;
	} else if (CLA == 0x84 && INS == 0x06 && P1 == 0x00 && P2 == 0x00) {
		*commandType = ECHO;
	} else {
		*commandType = NON_DEFINED_COMMAND;
	}
}


#include "../include/slave_scp03APDU_def.h"
#include "../include/slave_T1_def.h"

/*** BEGIN Static keys. ***/
uint8_t ENC_key[AES_KEY_LEN] = { 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
		0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01 }; /* SE static ENC key. */
uint8_t MAC_key[AES_KEY_LEN] = { 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
		0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02 }; /* SE static MAC key. */
/*** END Static keys. ***/

session_context_t scp03_sess_ctxt; /* Session context data. */

secure_object_t sec_objs[MAX_SEC_OBJ_NUM]; /* Array of secure objects stored in the SE. */

void set_rec_APDU_message(uint8_t *ptrRecAPDU) {
	if (ptrRecAPDU[4] != 0x00) {
		scp03_sess_ctxt.rx_APDU_header_len = 5;
		scp03_sess_ctxt.rx_APDU_data_len = ptrRecAPDU[4];
		memcpy(scp03_sess_ctxt.rx_APDU_message, ptrRecAPDU,
				scp03_sess_ctxt.rx_APDU_header_len
						+ scp03_sess_ctxt.rx_APDU_data_len);
	} else {
		scp03_sess_ctxt.rx_APDU_header_len = 7;
		scp03_sess_ctxt.rx_APDU_data_len = ptrRecAPDU[5];
		scp03_sess_ctxt.rx_APDU_data_len <<= 8;
		scp03_sess_ctxt.rx_APDU_data_len |= ptrRecAPDU[6];
		memcpy(scp03_sess_ctxt.rx_APDU_message, ptrRecAPDU,
				scp03_sess_ctxt.rx_APDU_header_len
						+ scp03_sess_ctxt.rx_APDU_data_len);
	}
}

void scp03APDU_construct_resp_APDU_message(uint8_t *ptrAPDUCommand,
		uint8_t *ptrAPDUResponse, uint8_t *ptrAPDUResponseLen) {
	set_rec_APDU_message(ptrAPDUCommand);
	get_command_type(&scp03_sess_ctxt.rx_APDU_command_type);

	if (scp03_sess_ctxt.rx_APDU_command_type <= EXTERNAL_AUTHENTICATE) { /* Secure channel session not yet established. */
		switch (scp03_sess_ctxt.rx_APDU_command_type) {
		case SELECT:
			CLI_printf("SELECT COMMAND\n");
			break;
		case INITIALIZE_UPDATE:
			CLI_printf("INIT UPDATE COMMAND\n");
			hal_toggle_gpio((uint8_t) CHANNEL_INIT_GPIO);
			initialize_update_response(ptrAPDUResponse, ptrAPDUResponseLen);
			hal_toggle_gpio((uint8_t) CHANNEL_INIT_GPIO);

			break;
		case EXTERNAL_AUTHENTICATE:
			CLI_printf("EXT AUTH COMMAND\n");
			hal_toggle_gpio((uint8_t) CHANNEL_INIT_GPIO);
			external_authenticate_response(ptrAPDUResponse, ptrAPDUResponseLen);
			hal_toggle_gpio((uint8_t) CHANNEL_INIT_GPIO);

			break;
		default:
			break;
		}
	} else if (scp03_sess_ctxt.rx_APDU_command_type < NON_DEFINED_COMMAND) { /* Assuming that the first commands have been successfully processed, the session has been established. */
		//CLI_printf("OTHER COMMAND\n");
		hal_toggle_gpio((uint8_t) CHANNEL_INIT_GPIO);
		prepare_response_APDU(ptrAPDUCommand, ptrAPDUResponse,
				ptrAPDUResponseLen);
	}
}

void initialize_update_response(uint8_t *ptrAPDUResponse,
		uint8_t *ptrAPDUResponseLen) {
	uint8_t card_cryptogram_full_len[CARD_CRYPTOGRAM_FULL_LEN]; /* SE complete card cryptogram. */
	uint8_t i; /* Counter/index. */

	/* 10 bytes key diversification data; 3 bytes key information; 8 bytes card challenge, 8 bytes card cryptogram; 3 bytes sequence counter. */

	/*** BEGIN Add key diversification data. ***/
	for (i = 0; i < 10; i++) {
		ptrAPDUResponse[i] = 0x01; /* Arbitrarily chosen values for the key diversification data. */
	}
	/*** END Add key diversification data. ***/

	/*** BEGIN Add key information. ***/
	ptrAPDUResponse[i++] = 0x0b; /* Key version number = P1 parameter in the INITIALIZE UPDATE command. */
	ptrAPDUResponse[i++] = 0x03; /* Secure channel protocol identifier. */
	ptrAPDUResponse[i++] = 0x00; /* "i" parameter. */
	/*** END Add key information. ***/

	/*** BEGIN Add card challenge. ***/
	scp03_sess_ctxt.card_challenge[0] = 0x44;
	scp03_sess_ctxt.card_challenge[1] = 0x21;
	scp03_sess_ctxt.card_challenge[2] = 0x35;
	scp03_sess_ctxt.card_challenge[3] = 0x55;
	scp03_sess_ctxt.card_challenge[4] = 0x52;
	scp03_sess_ctxt.card_challenge[5] = 0x00;
	scp03_sess_ctxt.card_challenge[6] = 0x10;
	scp03_sess_ctxt.card_challenge[7] = 0x11;
	memcpy(&ptrAPDUResponse[i], scp03_sess_ctxt.card_challenge,
	CARD_CHALLENGE_LEN);
	i += CARD_CHALLENGE_LEN;
	/*** END Add card challenge. ***/

	memcpy(scp03_sess_ctxt.host_challenge,
			&scp03_sess_ctxt.rx_APDU_message[scp03_sess_ctxt.rx_APDU_header_len],
			HOST_CHALLENGE_LEN); /* Retrieve host challenge. */

	/*** BEGIN Generate session keys. ***/
	//scp03aux_gen_S_ENC_KEY(&scp03_sess_ctxt, ENC_key);
	scp03aux_gen_session_key(&scp03_sess_ctxt, ENC_key, S_ENC);
	//scp03aux_gen_S_RMAC_KEY(&scp03_sess_ctxt, MAC_key);
	scp03aux_gen_session_key(&scp03_sess_ctxt, MAC_key, S_RMAC);
	//scp03aux_gen_S_MAC_KEY(&scp03_sess_ctxt, MAC_key);
	scp03aux_gen_session_key(&scp03_sess_ctxt, MAC_key, S_MAC);
	/*** END Generate session keys. ***/

	/*** BEGIN Generate card cryptogram. ***/
	scp03aux_gen_card_cryptogram(&scp03_sess_ctxt, card_cryptogram_full_len);
	memcpy(&ptrAPDUResponse[i], card_cryptogram_full_len,
			(CARD_CRYPTOGRAM_FULL_LEN / 2));
	i += CARD_CRYPTOGRAM_FULL_LEN / 2;
	/*** END Generate card cryptogram. ***/

	/*** BEGIN Add the SW bytes. ***/
	ptrAPDUResponse[i++] = 0x90;
	ptrAPDUResponse[i++] = 0x00;
	/*** END Add the SW bytes. ***/

	*ptrAPDUResponseLen = i; /* Update the APDU response message length. */
}

void external_authenticate_response(uint8_t *ptrAPDUResponse,
		uint8_t *ptrAPDUResponseLen) {
	uint8_t SW1, SW2; /* The SW bytes of the response APDU. */
	uint8_t i = 0; /* Counter. */
	bool_t isTrue_verify_host_cryptogram;
	bool_t isTrue_verify_MAC;

	memset(scp03_sess_ctxt.mac_chaining_value, 0x00, MCV_LEN); /* Initially, the MAC chaining value is a string of zeroes. */

	scp03aux_verify_host_cryptogram(&scp03_sess_ctxt,
			&isTrue_verify_host_cryptogram); /* Verify the received host cryptogram. */

	scp03aux_verify_rec_APDU_MAC(&scp03_sess_ctxt, &isTrue_verify_MAC); /* Verify the received APDU MAC. */

	if (isTrue_verify_host_cryptogram && isTrue_verify_MAC) { /* Authentication of host cryptogram OK. */
		scp03_sess_ctxt.curr_sec_level = scp03_sess_ctxt.rx_APDU_message[i_P1]; /* Set the current security level. */

		/*** BEGIN Set the SW bytes. ***/
		SW1 = 0x90;
		SW2 = 0x00;
		/*** END Set the SW bytes. ***/

		scp03aux_inc_command_counter(&scp03_sess_ctxt); /* Increment command counter. */
	} else { /* Authentication of host cryptogram failed and/or CMAC verification failed. */
		/*** BEGIN Set the SW bytes. ***/
		SW1 = 0x63;
		SW2 = 0x00;
		/*** END Set the SW bytes. ***/
	}

	/*** BEGIN Add the SW bytes. ***/
	ptrAPDUResponse[i++] = SW1;
	ptrAPDUResponse[i++] = SW2;
	/*** END Add the SW bytes. ***/

	*ptrAPDUResponseLen = i; /* Update the APDU response message length. */
}

void prepare_response_APDU(uint8_t *ptrAPDUCommand, uint8_t *ptrAPDUResponse,
		uint8_t *ptrAPDUResponseLen) {
	//CLI_printf("Prepare Response APDU BEGIN\n");

	uint8_t response_data[256]; /* The data (in clear) to be sent to the master. */
	uint8_t response_data_len; /* The length of the data (in clear) to be sent to the master. */
	uint8_t SW1, SW2; /* SW bytes of the response. */
	uint8_t command_data_dec[256]; /* The decrypted data received from the master. */
	uint8_t command_data_proper_len /* The length of the data field without the CMAC. */
	= scp03_sess_ctxt.rx_APDU_data_len - MAC_LEN;
	bool_t isTrue_verify_MAC; /* Is the calculated MAC the same as the received MAC? */
	//CLI_printf("Verify MAC BEGIN\n");

	hal_toggle_gpio((uint8_t) COMMAND_DECRYPT_AUTH_GPIO);

	scp03aux_verify_rec_APDU_MAC(&scp03_sess_ctxt, &isTrue_verify_MAC); /* Verify the received APDU MAC. */
	//CLI_printf("Verify MAC END\n");

	if (isTrue_verify_MAC) { /* Command processing OK. */
		/*** BEGIN Check if received data is encrypted. If so, decrypt it. ***/
		if (command_data_proper_len > 0
				&& (scp03_sess_ctxt.curr_sec_level == C_DEC_C_MAC
						|| scp03_sess_ctxt.curr_sec_level >= C_DEC_C_MAC_R_MAC)) {
			scp03aux_decrypt_com_APDU(&scp03_sess_ctxt, command_data_dec,
					&command_data_proper_len);
		} else { /* Data received from master is not encrypted. */
			memcpy(command_data_dec,
					&scp03_sess_ctxt.rx_APDU_message[scp03_sess_ctxt.rx_APDU_header_len],
					command_data_proper_len);
		}
		/*** END Check if received data is encrypted ***/
		hal_toggle_gpio((uint8_t) COMMAND_DECRYPT_AUTH_GPIO);

		switch (scp03_sess_ctxt.rx_APDU_command_type) {
		case GET_VERSION:
			get_version_response(response_data, &response_data_len);
			break;
		case CHECK_OBJECT_EXISTS:
			check_object_exists_response(response_data, &response_data_len,
					command_data_dec);
			break;
		case WRITE_ECKEY:
			write_eckey_response(response_data, &response_data_len,
					command_data_dec);
			break;
		case DELETE_SECURE_OBECT:
			delete_secure_object_response(response_data, &response_data_len,
					command_data_dec);
			break;
		case READ_OBJECT:
			read_object_response(response_data, &response_data_len,
					command_data_dec);
			break;
		case ECHO:
			echo_response(response_data, &response_data_len, command_data_dec);
			break;
		default:
			break;
		}

		/*** BEGIN Add the SW bytes. ***/
		SW1 = 0x90;
		SW2 = 0x00;
		/*** END Add the SW bytes. ***/
		hal_toggle_gpio((uint8_t) RESP_ENCRYPT_MAC_GPIO);

		scp03aux_apply_session_security_requirements_resp_APDU(&scp03_sess_ctxt,
				ptrAPDUResponse, ptrAPDUResponseLen, response_data,
				response_data_len, SW1, SW2); /* Apply the security requirements of the current SCP session. */

		scp03aux_inc_command_counter(&scp03_sess_ctxt); /* Increment command counter. Careful that the session security requirements should be applied with the non-incremented command counter values! */
		hal_toggle_gpio((uint8_t) RESP_ENCRYPT_MAC_GPIO);

	} else { /* Command processing failed. */
		response_data_len = 0; /* Set the response data length. */

		/*** BEGIN Add the SW bytes. ***/
		SW1 = 0x63;
		SW2 = 0x00;
		/*** END Add the SW bytes. ***/

		scp03aux_apply_session_security_requirements_resp_APDU(&scp03_sess_ctxt,
				ptrAPDUResponse, ptrAPDUResponseLen, response_data,
				response_data_len, SW1, SW2); /* Apply the security requirements of the current SCP session. */
	}

	/*** BEGIN Add the SW bytes while updating the length of the response message. ***/
	ptrAPDUResponse[(*ptrAPDUResponseLen)++] = SW1;
	ptrAPDUResponse[(*ptrAPDUResponseLen)++] = SW2;
	/*** END Add the SW bytes while updating the length of the response message. ***/

	//CLI_printf("Prepare Response APDU END\n");
}

void get_version_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen) {
	*ptrResponseDataLen = 7; /* Set the response data length. */
	ptrResponseData[0] = 0x41;
	ptrResponseData[1] = 0x05;
	for (uint8_t i = 2; i < *ptrResponseDataLen; i++) {
		ptrResponseData[i] = 0x00; /* Temporary values (arbitrarily chosen), should be checked. */
	}
}

void check_object_exists_response(uint8_t *ptrResponseData,
		uint8_t *ptrResponseDataLen, uint8_t *ptrCommandDataDec) {
	/*** BEGIN Prepare response packet data. ***/
	*ptrResponseDataLen = 3; /* Tag (1 byte), actual response data length (1 byte), actual response (1 byte). */
	ptrResponseData[0] = TAG_1; /* Tag. */
	ptrResponseData[1] = 0x01; /* Actual response data length. */
	ptrResponseData[2] = result_FAILURE; /* Actual response: failure, until otherwise proven. */
	for (uint8_t i = 0; i < MAX_SEC_OBJ_NUM; i++) {
		if (memcmp(sec_objs[i].object_identifier, &ptrCommandDataDec[2],
				ptrCommandDataDec[1]) == 0) {
			ptrResponseData[2] = result_SUCCESS; /* Success: the secure object already exists in the SE. */
			break;
		}
	}
	/*** END Prepare response packet data. ***/
}

void write_eckey_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen,
		uint8_t *ptrCommandDataDec) {
	uint8_t i; /* The index within the secure objects array of the target object. */
	uint8_t j; /* The first available cell within the secure objects array. */
	uint8_t key_pair_offset; /* The index denoting the start of the key pair (tag included) */

	/*** BEGIN Find the target secure object. ***/
	/* Object exists in the SE iff the final value of i is in {0, 1, ... MAX_SEC_OBJ_NUM-1}.
	 * If the secure object does not exist in the SE, find the first available free cell in the secure objects array, using variable 'j' as index. */
	j = MAX_SEC_OBJ_NUM;
	for (i = 0; i < MAX_SEC_OBJ_NUM; i++) {
		if (memcmp(sec_objs[i].object_identifier, &ptrCommandDataDec[2],
				ptrCommandDataDec[1]) == 0) {
			break;
		} else if (sec_objs[i].object_identifier[0] == 0x00) { /* An object identifier cannot start with a zero byte. This implies that the cell is available. */
			j = i;
			break;
		}
	}
	/*** END Find the target secure object. ***/

	/*** BEGIN Create/update secure object. ***/
	if (j < MAX_SEC_OBJ_NUM) { /* Implies that the secure object does not exist AND there is an available cell to store the new secure object. The value of variable 'j' indicates the index. */
		memcpy(sec_objs[j].object_identifier, &ptrCommandDataDec[2],
				ptrCommandDataDec[1]);
		sec_objs[j].authentication_indicator = 1; /* SET, because it is an authenticated object in this case. */
		key_pair_offset = 1 /* TAG */+ 1 /* length */+ ptrCommandDataDec[1] + 1 /* TAG */
		+ 1 /* length */+ ptrCommandDataDec[4];
		memcpy(sec_objs[j].data, &ptrCommandDataDec[key_pair_offset],
				scp03_sess_ctxt.rx_APDU_data_len - key_pair_offset);
	} else { /* Update the existing object, stored at position 'i' in the secure objects array. */
		/* Involves updating attributes such as "max attempts", etc. Not implemented. */
	}
	/*** END Create/update secure object. ***/

	/*** BEGIN Prepare response packet data. ***/
	*ptrResponseDataLen = 3;
	ptrResponseData[0] = TAG_1;
	ptrResponseData[1] = 0x01;
	ptrResponseData[2] = result_SUCCESS;
	/*** END Prepare response packet data. ***/
}

void delete_secure_object_response(uint8_t *ptrResponseData,
		uint8_t *ptrResponseDataLen, uint8_t *ptrCommandDataDec) {
	/*** BEGIN Prepare response packet data. ***/
	*ptrResponseDataLen = 0;
	/*** END Prepare response packet data. ***/
}

void read_object_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen,
		uint8_t *ptrCommandDataDec) {
	uint8_t i, k;

	/*** BEGIN Prepare response packet data. ***/
	for (i = 0; i < MAX_SEC_OBJ_NUM; i++) {
		if (memcmp(sec_objs[i].object_identifier, &ptrCommandDataDec[2],
				ptrCommandDataDec[1]) == 0) {
			break;
		}
	}
	for (k = 0; sec_objs[i].data[k] != TAG_4; k++)
		;
	k++;
	*ptrResponseDataLen = sec_objs[i].data[k] + 2;
	ptrResponseData[0] = TAG_1;
	ptrResponseData[1] = sec_objs[i].data[k]; /* Length of 'actual data'. */
	memcpy(&ptrResponseData[2], &sec_objs[i].data[k + 1], ptrResponseData[1]);
	/*** END Prepare response packet data. ***/
}

void echo_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen,
		uint8_t *ptrCommandDataDec) {
	*ptrResponseDataLen = scp03_sess_ctxt.rx_APDU_data_len - MAC_LEN;
	CLI_printf("Responding to echo with bytes: [",
			(*ptrResponseDataLen));
	for (uint32_t i = 0; i < 3; ++i) {
		CLI_printf(" 0x%x ", ptrCommandDataDec[i]);
	}
	CLI_printf(" ... ]\n");
	memcpy(ptrResponseData, ptrCommandDataDec, *ptrResponseDataLen);
}

void get_command_type(APDU_command_t *commandType) {
	uint8_t CLA, INS, P1, P2;

	CLA = scp03_sess_ctxt.rx_APDU_message[i_CLA];
	INS = scp03_sess_ctxt.rx_APDU_message[i_INS];
	P1 = scp03_sess_ctxt.rx_APDU_message[i_P1];
	P2 = scp03_sess_ctxt.rx_APDU_message[i_P2];

	if ((CLA >= 0x80 && CLA <= 0x83) && INS == 0x50) { /* INITIALIZE UPDATE */
		*commandType = INITIALIZE_UPDATE;
	} else if ((CLA >= 0x84 && CLA <= 0x87) && INS == 0x82) { /* EXTERNAL_AUTHENTICATE */
		*commandType = EXTERNAL_AUTHENTICATE;
	} else if (CLA == 0x00 && INS == 0xa4) { /* SELECT */
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

#include "../include/slave_scp03_aux_def.h"

mbedtls_aes_context aes_enc;
mbedtls_aes_context aes_dec;

volatile unsigned long t1;
volatile unsigned long t2;
volatile unsigned long diff;

extern volatile unsigned long count_AES_calls;
volatile unsigned long tot_AES_enc;
volatile unsigned long tot_AES_dec;

static void begin_num_AES_enc() {
	count_AES_calls = 0;
}

static void end_num_AES_enc() {
	tot_AES_enc = count_AES_calls;
}

static void begin_num_AES_dec() {
	count_AES_calls = 0;
}

static void end_num_AES_dec() {
	tot_AES_dec = count_AES_calls;
}

void scp03aux_verify_rec_APDU_MAC(session_context_t *scp03SessCtxt,
		bool_t *isTrue_status) {
	uint8_t in_Data[MAX_DATA_LEN]; /* Auxiliary variable, used for calculating the MAC of the received APDU message. */
	uint8_t MAC_offset; /* Position of the first byte of the MAC within the received APDU message string. */
	uint8_t calculated_MAC[MCV_LEN]; /* Calculated MAC value. */

	memcpy(in_Data, scp03SessCtxt->mac_chaining_value, MCV_LEN);
	MAC_offset = scp03SessCtxt->rx_APDU_header_len
			+ scp03SessCtxt->rx_APDU_data_len - MAC_LEN;
	memcpy(&in_Data[MCV_LEN], scp03SessCtxt->rx_APDU_message, MAC_offset);
	//CLI_printf("calculate_CMAC BEGIN\n");
	calculate_CMAC(scp03SessCtxt->S_MAC_key, AES_KEY_LEN, in_Data,
			MCV_LEN + MAC_offset, calculated_MAC);
	//CLI_printf("calculate_CMAC END\n");

	if (memcmp(calculated_MAC, &scp03SessCtxt->rx_APDU_message[MAC_offset],
			MAC_LEN) != 0) {
		*isTrue_status = FALSE;
	} else {
		*isTrue_status = TRUE;
		memcpy(scp03SessCtxt->mac_chaining_value, calculated_MAC, MCV_LEN); /* Update the MAC chaining value. */
	}
}

void scp03aux_verify_host_cryptogram(session_context_t *scp03SessCtxt,
		bool_t *isTrue_status) {
	uint8_t in_Data[MAX_DATA_LEN];
	uint16_t in_Data_len;
	uint8_t calculated_host_cryptogram[HOST_CRYPTOGRAM_LEN];

	/* Step 1: Prepare the necessary data to derive the host cryptogram. */
	memcpy(in_Data, scp03SessCtxt->host_challenge, HOST_CHALLENGE_LEN);
	memcpy(&in_Data[HOST_CHALLENGE_LEN], scp03SessCtxt->card_challenge,
			CARD_CHALLENGE_LEN);
	in_Data_len = DDA_BUFFER_LEN;
	set_derivation_data(&in_Data[HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN],
			&in_Data_len, DATA_HOST_CRYPTOGRAM, DATA_DERIVATION_L_64BIT,
			DATA_DERIVATION_KDF_CTR, in_Data,
			HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN);
	/* Step 2: Calculate the host cryptogram. out_Data in this case is the calculated MAC value. */
	calculate_CMAC(scp03SessCtxt->S_MAC_key, AES_KEY_LEN,
			&in_Data[HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN], in_Data_len,
			calculated_host_cryptogram);
	/* Step 3: Compare the calculated host cryptogram with the received host cryptogram. */
	if (memcmp(calculated_host_cryptogram,
			&scp03SessCtxt->rx_APDU_message[scp03SessCtxt->rx_APDU_header_len],
			HOST_CRYPTOGRAM_LEN) != 0) {
		*isTrue_status = FALSE;
	} else {
		*isTrue_status = TRUE;
	}
}

void scp03aux_apply_session_security_requirements_resp_APDU(
		session_context_t *scp03SessCtxt, uint8_t *ptrAPDUResponse,
		uint8_t *ptrAPDUResponseLen, uint8_t *responseData,
		uint8_t responseDataLen, uint8_t SW1, uint8_t SW2) {
	uint8_t padded_data_len; /* Padded data length. */
	uint8_t response_data_enc[256]; /* Encrypted response data. */
	uint8_t in_Data[256]; /* Auxiliary variable, used for calculating the RMAC of the response APDU. */
	uint8_t r_MAC[16]; /* The RMAC of the response. */

	if (scp03SessCtxt->curr_sec_level == C_DEC_R_ENC_C_MAC_R_MAC
			&& responseDataLen > 0) { /* If true, response data should be encrypted. */
		encrypt_resp_APDU(scp03SessCtxt, response_data_enc, &padded_data_len,
				responseData, responseDataLen);

		memcpy(ptrAPDUResponse, response_data_enc, padded_data_len);
		*ptrAPDUResponseLen = padded_data_len; /* Update the response message length. */
	} else {
		memcpy(ptrAPDUResponse, responseData, responseDataLen);
		*ptrAPDUResponseLen = responseDataLen;
	}
	if (scp03SessCtxt->curr_sec_level >= C_MAC_R_MAC) { /* If true, response should come with an RMAC tag appended. */
		memcpy(in_Data, scp03SessCtxt->mac_chaining_value, MCV_LEN);
		memcpy(&in_Data[MCV_LEN], ptrAPDUResponse, *ptrAPDUResponseLen);
		in_Data[MCV_LEN + *ptrAPDUResponseLen] = SW1;
		in_Data[MCV_LEN + *ptrAPDUResponseLen + 1] = SW2;

		calculate_CMAC(scp03SessCtxt->S_RMAC_key, AES_KEY_LEN, in_Data,
				MCV_LEN + *ptrAPDUResponseLen + 2, r_MAC); /* Calculate the response APDU RMAC. */

		memcpy(&ptrAPDUResponse[*ptrAPDUResponseLen], r_MAC, MAC_LEN); /* Construct the packet to be sent, adding the RMAC tag. */

		*ptrAPDUResponseLen += MAC_LEN; /* Update the length of the response message. */
	}
}

void encrypt_resp_APDU(session_context_t *scp03SessCtxt,
		uint8_t *ptrResponseDataEnc, uint8_t *ptrPaddedDataLen,
		uint8_t *ptrResponseData, uint8_t responseDataLen) {
	uint8_t iv[16] = { 0 }; /* IV used for encryption. */

	/* BEGIN Pad prior to encryption. */
	ptrResponseData[responseDataLen] = 0x80;
	*ptrPaddedDataLen = ((uint8_t) (responseDataLen / AES_BLOCK_LEN)
			+ ((responseDataLen % AES_BLOCK_LEN) > 0 ? 1 : 0)) * AES_BLOCK_LEN;
	for (int i = responseDataLen + 1; i < *ptrPaddedDataLen; i++) {
		ptrResponseData[i] = 0x00;
	}
	/* END Pad prior to encryption. */

	/* BEGIN Encrypt the data to be sent to the master. */
	get_response_ICV(scp03SessCtxt, iv); /* Calculate the ICV. */
	mbedtls_aes_crypt_cbc(&aes_enc, MBEDTLS_AES_ENCRYPT, *ptrPaddedDataLen, iv,
			ptrResponseData, ptrResponseDataEnc);
	/* END Encrypt the data to be sent to the master. */
}

void scp03aux_decrypt_com_APDU(session_context_t *scp03SessCtxt,
		uint8_t *ptrCommandDataDec, uint8_t *ptrCommandDataProperLen) {
	uint8_t command_data_enc[256];
	uint8_t iv[16] = { 0 }; /* ICV for data decryption. */

	get_command_ICV(scp03SessCtxt, iv); /* Calculate the ICV. */
	memcpy(command_data_enc, iv, AES_BLOCK_LEN);
	memcpy(&command_data_enc[AES_BLOCK_LEN],
			&scp03SessCtxt->rx_APDU_message[scp03SessCtxt->rx_APDU_header_len],
			*ptrCommandDataProperLen);

	mbedtls_aes_crypt_cbc(&aes_dec, MBEDTLS_AES_DECRYPT,
			*ptrCommandDataProperLen, iv, &command_data_enc[AES_BLOCK_LEN],
			ptrCommandDataDec);
}

void get_response_ICV(session_context_t *scp03SessCtxt, uint8_t *pIcv) {
	uint8_t iv_Zero[SCP_IV_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t padded_counter_block[SCP_IV_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t temp_iv[SCP_IV_SIZE] = { 0 };

	memcpy(padded_counter_block, scp03SessCtxt->command_counter, SCP_KEY_SIZE);
	padded_counter_block[0] = 0x80; /* MSB padded with 0x80, as per the SCP03 spec. */

	mbedtls_aes_crypt_cbc(&aes_enc, MBEDTLS_AES_ENCRYPT, SCP_KEY_SIZE, iv_Zero,
			padded_counter_block, temp_iv);
	memcpy(pIcv, temp_iv, SCP_IV_SIZE);
}

void get_command_ICV(session_context_t *scp03SessCtxt, uint8_t *pIcv) {
	uint8_t iv_Zero[SCP_IV_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t padded_counter_block[SCP_IV_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t temp_iv[SCP_IV_SIZE] = { 0 };

	memcpy(padded_counter_block, scp03SessCtxt->command_counter, SCP_KEY_SIZE);

	mbedtls_aes_crypt_cbc(&aes_enc, MBEDTLS_AES_ENCRYPT, SCP_KEY_SIZE, iv_Zero,
			padded_counter_block, temp_iv);
	memcpy(pIcv, temp_iv, SCP_IV_SIZE);
}

void generate_session_key(uint8_t *key, size_t keyLen, uint8_t *inData,
		size_t inDataLen, uint8_t *outSignature) {
	calculate_CMAC(key, keyLen, inData, inDataLen, outSignature);
}

void calculate_CMAC(uint8_t *key, size_t keyLen, uint8_t *inData,
		size_t inDataLen, uint8_t *outSignature) {
	mbedtls_cipher_context_t c_ctx;
	const mbedtls_cipher_info_t *cipher_info;

	cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

	//CLI_printf("mbedtls_cipher_init BEGIN\n");
	mbedtls_cipher_init(&c_ctx);
	//CLI_printf("mbedtls_cipher_init END\n");

	//CLI_printf("mbedtls_cipher_setup BEGIN\n");
	mbedtls_cipher_setup(&c_ctx, cipher_info);
	//Si bloccava qua
	//CLI_printf("mbedtls_cipher_setup END\n");

	//CLI_printf("mbedtls_cipher_cmac_starts BEGIN\n");
	mbedtls_cipher_cmac_starts(&c_ctx, key, 128);
	//CLI_printf("mbedtls_cipher_cmac_starts END\n");

	mbedtls_cipher_cmac_update(&c_ctx, inData, inDataLen);

	mbedtls_cipher_cmac_finish(&c_ctx, outSignature);
}

void set_derivation_data(uint8_t *ddA, uint16_t *pDdALen, uint8_t ddConstant,
		uint16_t ddL, uint8_t iCounter, const uint8_t *context,
		uint16_t contextLen) {
	memset(ddA, 0, DD_LABEL_LEN - 1);
	ddA[DD_LABEL_LEN - 1] = ddConstant;
	ddA[DD_LABEL_LEN] = 0x00; /* Separation indicator. */
	ddA[DD_LABEL_LEN + 1] = (uint8_t) (ddL >> 8);
	ddA[DD_LABEL_LEN + 2] = (uint8_t) ddL;
	ddA[DD_LABEL_LEN + 3] = iCounter;
	memcpy(&ddA[DD_LABEL_LEN + 4], context, contextLen);
	*pDdALen = DD_LABEL_LEN + 4 + contextLen;
}

void scp03aux_gen_card_cryptogram(session_context_t *scp03SessCtxt,
		uint8_t *cardCryptogram) {
	uint8_t ddA[DDA_BUFFER_LEN];
	uint16_t ddALen = DDA_BUFFER_LEN;
	uint8_t context[HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN];
	uint16_t contextLen = 0;

	memcpy(context, scp03SessCtxt->host_challenge, HOST_CHALLENGE_LEN);
	memcpy(&context[HOST_CHALLENGE_LEN], scp03SessCtxt->card_challenge,
			CARD_CHALLENGE_LEN);
	contextLen = HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN;

	set_derivation_data(ddA, &ddALen, DATA_CARD_CRYPTOGRAM,
			DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context,
			contextLen);

	calculate_CMAC(scp03SessCtxt->S_MAC_key, AES_KEY_LEN, ddA, ddALen,
			cardCryptogram);
}

void scp03aux_gen_session_key(session_context_t *scp03SessCtxt,
		uint8_t *staticKey, session_key_t sessionKey) {
	uint8_t ddA[DDA_BUFFER_LEN];
	uint16_t ddALen = DDA_BUFFER_LEN;
	uint8_t context[HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN];
	uint16_t contextLen = 0;

	memcpy(context, scp03SessCtxt->host_challenge, HOST_CHALLENGE_LEN);
	memcpy(&context[HOST_CHALLENGE_LEN], scp03SessCtxt->card_challenge,
			CARD_CHALLENGE_LEN);
	contextLen = HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN;

	if (sessionKey == S_ENC) {
		set_derivation_data(ddA, &ddALen, DATA_DERIVATION_SENC,
				DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context,
				contextLen);
		generate_session_key(staticKey, AES_KEY_LEN, ddA, ddALen,
				scp03SessCtxt->S_ENC_key);
		mbedtls_aes_setkey_enc(&aes_enc, scp03SessCtxt->S_ENC_key, 128);
		mbedtls_aes_setkey_dec(&aes_dec, scp03SessCtxt->S_ENC_key, 128);
	} else if (sessionKey == S_MAC) {
		set_derivation_data(ddA, &ddALen, DATA_DERIVATION_SMAC,
				DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context,
				contextLen);
		generate_session_key(staticKey, AES_KEY_LEN, ddA, ddALen,
				scp03SessCtxt->S_MAC_key);
	} else {
		set_derivation_data(ddA, &ddALen, DATA_DERIVATION_SRMAC,
				DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context,
				contextLen);
		generate_session_key(staticKey, AES_KEY_LEN, ddA, ddALen,
				scp03SessCtxt->S_RMAC_key);
	}
}

void scp03aux_inc_command_counter(session_context_t *scp03SessCtxt) {
	int i = 15;

	while (i > 0) {
		if (scp03SessCtxt->command_counter[i] < 255) {
			scp03SessCtxt->command_counter[i] += 1;
			break;
		} else {
			scp03SessCtxt->command_counter[i] = 0;
			i--;
		}
	}
	return;
}

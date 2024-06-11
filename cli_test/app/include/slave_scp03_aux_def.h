#ifndef INC_SLAVE_SCP03_AUX_DEF_H_
#define INC_SLAVE_SCP03_AUX_DEF_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/include/mbedtls/aes.h"
#include "mbedtls/include/mbedtls/cmac.h"

/* Length values denote number of bytes, unless otherwise specified. */
/* Constants related to cryptographic functions. */
#define AES_KEY_LEN 16
#define AES_BLOCK_LEN 16
#define HOST_CHALLENGE_LEN 8
#define CARD_CHALLENGE_LEN 8
#define CARD_CRYPTOGRAM_FULL_LEN 16
#define HOST_CRYPTOGRAM_LEN 8
#define MCV_LEN 16
#define MAC_LEN 8
#define COMMAND_COUNTER 16
#define SCP_IV_SIZE 16
#define SCP_KEY_SIZE 16

/* Constants related to the data derivation process. */
#define DATA_CARD_CRYPTOGRAM (0x00)
#define DATA_HOST_CRYPTOGRAM (0x01)
#define DATA_DERIVATION_SENC (0x04)
#define DATA_DERIVATION_SMAC (0x06)
#define DATA_DERIVATION_SRMAC (0x07)
#define DATA_DERIVATION_L_64BIT 0x0040
#define DATA_DERIVATION_L_128BIT 0x0080
#define DATA_DERIVATION_KDF_CTR 0x01
#define DD_LABEL_LEN 12
#define CONTEXT_LENGTH (HOST_CHALLENGE_LEN + CARD_CHALLENGE_LEN)
#define DDA_BUFFER_LEN (CONTEXT_LENGTH + DD_LABEL_LEN + 16)

/* Constants related to the security level of the secure protocol channel session. */
#define NO_SECURITY_LEVEL 0x00
#define AUTHENTICATED 0x00 /* Check this... */
#define C_MAC 0x01
#define C_DEC_C_MAC 0x03
#define C_MAC_R_MAC 0x11
#define C_DEC_C_MAC_R_MAC 0x13
#define C_DEC_R_ENC_C_MAC_R_MAC 0x33

#define MAX_DATA_LEN 256

/* Positions of the CLA, INS, P1, P2 bytes within the command APDU. */
#define i_CLA 0
#define i_INS 1
#define i_P1 2
#define i_P2 3

/* The maximum number of secure objects that can be stored in the SE. Value chosen arbitrarily. */
#define MAX_SEC_OBJ_NUM 10

typedef enum {
	SELECT,
	INITIALIZE_UPDATE,
	EXTERNAL_AUTHENTICATE,
	GET_VERSION,
	CHECK_OBJECT_EXISTS,
	WRITE_ECKEY,
	DELETE_SECURE_OBECT,
	READ_OBJECT,
	ECHO,
	NON_DEFINED_COMMAND
} APDU_command_t;

typedef struct {
	uint8_t rx_APDU_message[MAX_DATA_LEN];
	APDU_command_t rx_APDU_command_type;
	uint8_t rx_APDU_header_len;
	uint16_t rx_APDU_data_len;
	uint8_t S_ENC_key[AES_KEY_LEN];
	uint8_t S_MAC_key[AES_KEY_LEN];
	uint8_t S_RMAC_key[AES_KEY_LEN];
	uint8_t card_challenge[CARD_CHALLENGE_LEN];
	uint8_t host_challenge[HOST_CHALLENGE_LEN];
	uint8_t mac_chaining_value[MCV_LEN];
	uint8_t command_counter[AES_BLOCK_LEN];
	uint8_t curr_sec_level;
} session_context_t;

typedef struct {
	uint8_t object_class;
	uint8_t authentication_attempts[2];
	uint8_t max_authentication_attempts[2];
} authenticated_object_t;

typedef struct {
	uint8_t object_type;
	uint8_t min_tag_len_aead[2];
	uint8_t min_output_len[2];
} non_authenticated_object_t;

typedef struct {
	uint8_t object_identifier[4];
	uint8_t authentication_indicator;
	uint8_t session_owner_identifier[4];
	uint8_t policy[4]; /* Check this, it is of variable size. */
	uint8_t origin;
	uint8_t version[4];
	uint8_t data[MAX_DATA_LEN]; /* This field was added by me. */
	union {
		authenticated_object_t auth_obj;
		non_authenticated_object_t non_auth_obj;
	};
} secure_object_t;

typedef enum {
	result_NA = 0x00,
	result_SUCCESS = 0x01,
	result_FAILURE = 0x02,
} result_t;

typedef enum
{
    /** Invalid */
    TAG_NA                 = 0,
    TAG_SESSION_ID         = 0x10,
    TAG_POLICY             = 0x11,
    TAG_MAX_ATTEMPTS       = 0x12,
    TAG_IMPORT_AUTH_DATA   = 0x13,
    TAG_IMPORT_AUTH_KEY_ID = 0x14,
    TAG_POLICY_CHECK       = 0x15,
    TAG_1                  = 0x41,
    TAG_2                  = 0x42,
    TAG_3                  = 0x43,
    TAG_4                  = 0x44,
    TAG_5                  = 0x45,
    TAG_6                  = 0x46,
    TAG_7                  = 0x47,
    TAG_8                  = 0x48,
    TAG_9                  = 0x49,
    TAG_10                 = 0x4A,
    TAG_11                 = 0x4B,
} TAG_t;

typedef enum {
	TRUE = 1,
	FALSE = 0
} bool_t;

typedef enum {
	S_ENC,
	S_MAC,
	S_RMAC
} session_key_t;

/** scp03aux_verify_rec_APDU_MAC
 *
 * Compares the received APDU command CMAC with the calculated CMAC.
 *
 * @param[in]		scp03SessCtxt		Pointer to the session context variable.
 * @param[in,out]	isTrue_status		Pointer to the variable indicating the result of the comparison.
 */
void scp03aux_verify_rec_APDU_MAC(session_context_t *scp03SessCtxt, bool_t *isTrue_status);

/** scp03aux_verify_host_cryptogram
 *
 * Compares the received host cryptogram with the calculated host cryptogram.
 *
 * @param[in]		scp03SessCtxt		Pointer to the session context variable.
 * @param[in,out]	isTrue_status		Pointer to the variable indicating the result of the comparison.
 */
void scp03aux_verify_host_cryptogram(session_context_t *scp03SessCtxt, bool_t  *isTrue_status);

/** scp03aux_apply_session_security_requirements_resp_APDU
 *
 * Applies the SCP channel session security requirements to the response APDU.
 *
 * @param[in]		scp03SessCtxt		Pointer to the session context variable.
 * @param[in,out]	ptrAPDUResponse		The generated APDU response, after applying the session security requirements.
 * @param[in,out]	ptrAPDUResponseLen	The length of the generated APDU response, after applying the session security requirements.
 * @param[in]		responseData		The data field (in clear) of the response APDU.
 * @param[in]		responseDataLen 	The length of the data field (in clear).
 * @param[in]		SW1					The first SW byte of the response APDU.
 * @param[in]		SW2					The second SW byte of the response APDU.
 */
void scp03aux_apply_session_security_requirements_resp_APDU(session_context_t *scp03SessCtxt, uint8_t *ptrAPDUResponse, uint8_t *ptrAPDUResponseLen, uint8_t *responseData, uint8_t responseDataLen, uint8_t SW1, uint8_t SW2);

/** encrypt_resp_APDU
 *
 * Encrypts the data of the response APDU.
 *
 * @param[in]		scp03SessCtxt				Pointer to the session context variable.
 * @param[in,out]	ptrResponseDataEnc			The encrypted data to be sent as response.
 * @param[in,out]	ptrPaddedDataLen			Size of the encrypted data (padding is applied before encryption, hence the variable name).
 * @param[in,out]	ptrResponseData				The response data (in clear).
 * @param[in]		responseDataLen				Size of the response data (in clear).
 */
void encrypt_resp_APDU(session_context_t *scp03SessCtxt, uint8_t *ptrResponseDataEnc, uint8_t *ptrPaddedDataLen, uint8_t *ptrResponseData, uint8_t responseDataLen);

/** scp03aux_decrypt_com_APDU
 *
 * Decrypts the data of the received APDU command.
 *
 * @param[in]		scp03SessCtxt				Pointer to the session context variable.
 * @param[in,out]	ptrCommandDataDec			The decrypted data.
 * @param[in,out]	ptrCommandDataProperLen		Size of the decrypted data.
 */
void scp03aux_decrypt_com_APDU(session_context_t *scp03SessCtxt, uint8_t *ptrCommandDataDec, uint8_t *ptrCommandDataProperLen);

/** get_response_ICV
 *
 * Calculates the ICV to be used in APDU response encryption/decryption.
 *
 * @param[in]		scp03SessCtxt		Pointer to the session context variable.
 * @param[in,out]	pIcv				The calculated ICV.
 */
void get_response_ICV(session_context_t *scp03SessCtxt, uint8_t *pIcv);

/** get_command_ICV
 *
 * Calculates the ICV to be used in APDU command encryption/decryption.
 *
 * @param[in]		scp03SessCtxt		Pointer to the session context variable.
 * @param[in,out]	pIcv				The calculated ICV.
 */
void get_command_ICV(session_context_t *scp03SessCtxt, uint8_t *pIcv);

/** generate_session_key
 *
 * Generates the session key required for the channel.
 *
 * @param[in] 		key				Static key used to derive the session key.
 * @param[in] 		keyLen			Static key length.
 * @param[in] 		inData			Derivation data used in deriving the session key.
 * @param[in] 		inDataLen		Derivation data length.
 * @param[in,out]	outSignature	The generated session key.
 */
void generate_session_key(uint8_t *key, size_t keyLen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature);

/** calculate_CMAC
 *
 * Calculates CMAC.
 *
 * @param[in] 		key				Static key used in the CMAC calculation.
 * @param[in] 		keyLen			Static key length.
 * @param[in] 		inData			Derivation data used in deriving the session key.
 * @param[in] 		inDataLen		Derivation data length.
 * @param[in,out]	outSignature	The calculated CMAC.
 */
void calculate_CMAC(uint8_t *key, size_t keyLen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature);

/** set_derivation_data
 *
 * Prepares the derivation data necessary for deriving the session keys, card cryptogram, etc.
 *
 * @param[in,out]	ddA			Derivation data.
 * @param[in,out]	pddALen		Derivation data length.
 * @param[in] 		ddConstant	Specifies the type of data to be derived (session ENC key, session MAC key, card cryptogram, etc.).
 * @param[in] 		ddL			Derived data length.
 * @param[in] 		iCounter	Counter used in the data derivation process (NIST SP 800-38b).
 * @param[in] 		context		Concatenation of host challenge and card challenge (GlobalPlatform specification).
 * @param[in] 		contexLen	Length of context data.
 */
void set_derivation_data(uint8_t *ddA, uint16_t *pDdALen, uint8_t ddConstant, uint16_t ddL, uint8_t iCounter, const uint8_t *context, uint16_t contextLen);

/** scp03aux_gen_card_cryptogram
 *
 * Generates the card cryptogram.
 *
 * @param[in]			scp03SessCtxt			Pointer to the session context variable.
 * @param[in,out]		cardCryptogram			Array that will contain the calculated card cryptogram value.
 */
void scp03aux_gen_card_cryptogram(session_context_t *scp03SessCtxt, uint8_t *cardCryptogram);

/** scp03aux_gen_S_ENC_KEY
 *
 * Generates the session ENC key (member of the session context structure).
 *
 * @param[in,out]	scp03SessCtxt		Pointer to the session context variable.
 * @param[in]		staticKey			Pointer to the static key used to derive the session key.
 */
//void scp03aux_gen_S_ENC_KEY(session_context_t *scp03SessCtxt, uint8_t *staticKey);

/** scp03aux_gen_S_MAC_KEY
 *
 * Generates the session MAC key (member of the session context structure).
 *
 * @param[in,out]	scp03SessCtxt		Pointer to the session context variable.
 * @param[in]		staticKey			Pointer to the static key used to derive the session key.
 */
//void scp03aux_gen_S_MAC_KEY(session_context_t *scp03SessCtxt, uint8_t *staticKey);

/** scp03aux_gen_S_RMAC_KEY
 *
 * Generates the session RMAC key (member of the session context structure).
 *
 * @param[in,out]	scp03SessCtxt		Pointer to the session context variable.
 * @param[in]		staticKey			Pointer to the static key used to derive the session key.
 */
//void scp03aux_gen_S_RMAC_KEY(session_context_t *scp03SessCtxt, uint8_t *staticKey);

void scp03aux_gen_session_key(session_context_t *scp03SessCtxt, uint8_t *staticKey, session_key_t sessionKey);

/** scp03aux_inc_command_counter
 *
 * Increments the command counter (member of the session context structure).
 *
 * @param[in,out]	scp03SessCtxt		Pointer to the session context variable.
 */
void scp03aux_inc_command_counter(session_context_t *scp03SessCtxt);

#endif /* INC_SLAVE_SCP03_AUX_DEF_H_ */

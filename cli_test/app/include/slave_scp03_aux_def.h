#ifndef INC_SLAVE_SCP03_AUX_DEF_H_
#define INC_SLAVE_SCP03_AUX_DEF_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xoodyak2/api.h"
#include "xoodyak2/Xoodyak.h"

#define STATIC_KEY_LEN 16
#define AUTH_TAG_LEN 16
#define NONCE_LEN 16

#define MAX_DATA_LEN 1024

/* Positions of the CLA, INS, P1, P2 bytes within the command APDU. */
#define i_CLA 0
#define i_INS 1
#define i_P1 2
#define i_P2 3

#define RAPDU_HEADER_LEN 4 /* CLA, INS, Lc1, Lc2 */
#define iLC2RAPDU (RAPDU_HEADER_LEN - 1)
#define iLC1RAPDU (RAPDU_HEADER_LEN - 2)

#define CAPDU_HEADER_LEN 6 /* CLA INS, P1, P2, Lc1, Lc2 */
#define iLC2CAPDU (CAPDU_HEADER_LEN - 1)
#define iLC1CAPDU (CAPDU_HEADER_LEN - 2)

typedef enum {
	SELECT,
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
	uint16_t rx_APDU_data_len;
} session_context_t;

typedef enum {
	TRUE = 1, FALSE = 0
} bool_t;

typedef enum {
	UNINITIATED, HANDSHAKE, ACTIVE
} session_state_t;

void scp03aux_command_dec(session_context_t *scp03SessCtxt,
		uint8_t *decCommandBuf, uint8_t *isTrueVerifyMAC);

void scp03aux_response_enc(uint8_t *responseBuf);

#endif /* INC_SLAVE_SCP03_AUX_DEF_H_ */

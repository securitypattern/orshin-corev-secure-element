#ifndef INC_SLAVE_SCP03APDU_DEF_H_
#define INC_SLAVE_SCP03APDU_DEF_H_

#include <stdint.h>
#include "slave_scp03_aux_def.h"

/** set_rec_APDU_message
 *
 * @param[in]	ptrRecAPDU	Buffer containing the received APDU message from the master.
 */
void set_rec_APDU_message(uint8_t *ptrRecAPDU);

/** construct_resp_APDU_message
 *
 * Constructs the response APDU message.
 *
 * @param[in]		ptrAPDUCommand		The APDU command received from the master.
 * @param[in,out]	ptrAPDUResponse		The APDU response to be sent to the master.
 * @param[in,out]	ptrAPDUResponseLen	The length of the APDU response.
 */
void scp03APDU_construct_resp_APDU_message(uint8_t *ptrAPDUCommand, uint8_t *ptrAPDUResponse, uint8_t *ptrAPDUResponseLen);

/** prepare_response_APDU
 *
 * Prepares the response to an APDU command received from the master after an SCP session has been established.
 *
 * @param[in]		ptrAPDUCommand		The APDU command received from the master.
 * @param[in,out]	ptrAPDUResponse		The APDU response to be sent to the master.
 * @param[in,out]	ptrAPDUResponseLen	The length of the APDU response.
 */
void prepare_response_APDU(uint8_t *ptrAPDUCommand, uint8_t *ptrAPDUResponse, uint8_t *ptrAPDUResponseLen);


void echo_response(uint8_t *ptrResponseData, uint8_t *ptrResponseDataLen, uint8_t *ptrCommandDataDec);

/** get_command_type
 *
 * Determines the received APDU command type.
 *
 * @param[in,out]	commandType		Command type.
 */
void get_command_type(APDU_command_t *commandType);

#endif /* INC_SLAVE_SCP03APDU_DEF_H_ */

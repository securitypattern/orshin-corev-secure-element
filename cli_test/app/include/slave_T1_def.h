/*

Copyright (c) 2025, Security Pattern s.r.l. All rights reserved.
SPDX-License-Identifier: MIT

*/


#include <stdint.h>
#include <string.h>

#include "slave_scp03APDU_def.h"

#define CHANNEL_INIT_GPIO 0
#define COMMAND_DECRYPT_AUTH_GPIO 1
#define RESP_ENCRYPT_MAC_GPIO 2

#define T1_HEADER_LEN 3

/* Block types defined in the ISO IEC 7816-3 document. */
#define S_BLOCK 1
#define R_BLOCK 2
#define I_BLOCK 3

typedef struct {
	uint8_t NAD;
	uint8_t PCB;
	uint8_t LEN;
	uint8_t APDU_message[MAX_DATA_LEN];
	uint8_t CRC_B1;
	uint8_t CRC_B2;
} packet_t;

/** T1_generate_response
 *
 * Generates the response to be sent to the master.
 *
 * @param[in,out]	ptrRespBuffer	The generated response.
 */
void T1_generate_response(uint8_t *ptrRespBuffer);

/** parse_rec_packet
 *
 * Parses the received data.
 *
 * @param[in]	ptrRecBuffer	Buffer containing the received data.
 */
void T1_parse_rec_packet(uint8_t *ptrRecBuffer);

/** T1_construct_resp_packet_data
 *
 * Constructs the response packet to be sent to the master.
 */
void T1_construct_resp_packet_data();

/** construct_resp_packet_CRC
 *
 * Calculates the CRC bytes of the response packet.
 *
 * @param[in]	ptrRespBuffer	Pointer to the response buffer.
 */
void construct_resp_packet_CRC(uint8_t *ptrRespBuffer);

/** calc_crc
 *
 * Calculates the value of the CRC bytes.
 *
 * @param[in]		buffer		Data for which the CRC bytes are to be calculated.
 * @param[in] 		length		Length of the data.
 * @param[in,out]	crcFirst	First CRC byte calculated by the function.
 * @param[in,out]	crcSecond	Second CRC byte calculated by the function.
 */
void calc_crc(uint8_t *buffer, uint32_t length, uint8_t *crcFirst,
		uint8_t *crcSecond);

/** gen_resp_packet_PCB
 *
 * Generates the value of the response packet PCB byte.
 *
 * @return	The value of the response packet PCB byte.
 */
uint8_t gen_resp_packet_PCB();

/** get_block_type
 *
 * Determines the block type (S block, R block, or I block).
 *
 * @return	The block type.
 */
uint8_t get_block_type();

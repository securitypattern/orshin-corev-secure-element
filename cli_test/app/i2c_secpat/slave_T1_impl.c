#include "../include/slave_T1_def.h"
#include "../include/secpat_i2c.h"

packet_t rx_packet;
/* Packet received from the master. */
packet_t tx_packet;
/* Packet to be sent to the master. */


void T1_generate_response(uint8_t *ptrRespBuffer){
	tx_packet.NAD = (rx_packet.NAD << 4) | (rx_packet.NAD >> 4);
	ptrRespBuffer[0] = tx_packet.NAD;
	tx_packet.PCB = gen_resp_packet_PCB();
	ptrRespBuffer[1] = tx_packet.PCB;
	ptrRespBuffer[2] = tx_packet.LEN;
	memcpy(&ptrRespBuffer[T1_HEADER_LEN], tx_packet.APDU_message, tx_packet.LEN);
	construct_resp_packet_CRC(ptrRespBuffer);
	ptrRespBuffer[T1_HEADER_LEN + tx_packet.LEN] = tx_packet.CRC_B1;
	ptrRespBuffer[T1_HEADER_LEN + tx_packet.LEN + 1] = tx_packet.CRC_B2;
}

/*
void T1_parse_rec_packet(uint8_t *ptrRecBuffer){
	rx_packet.NAD = ptrRecBuffer[0];
	rx_packet.PCB = ptrRecBuffer[1];
	rx_packet.LEN = ptrRecBuffer[2];
	memcpy(rx_packet.APDU_message, &ptrRecBuffer[T1_HEADER_LEN], rx_packet.LEN);
	rx_packet.CRC_B1 = ptrRecBuffer[T1_HEADER_LEN + rx_packet.LEN];
	rx_packet.CRC_B2 = ptrRecBuffer[T1_HEADER_LEN + rx_packet.LEN + 1];
}
*/

void T1_construct_resp_packet_data(){
	scp03APDU_construct_resp_APDU_message(rx_packet.APDU_message, tx_packet.APDU_message, &tx_packet.LEN);
}

void construct_resp_packet_CRC(uint8_t *ptrRespBuffer){
	calc_crc(ptrRespBuffer, T1_HEADER_LEN + tx_packet.LEN, &tx_packet.CRC_B1, &tx_packet.CRC_B2);
}

void calc_crc(uint8_t *buffer, uint32_t length, uint8_t *crcFirst, uint8_t *crcSecond)
{
    uint16_t cal_crc = 0xFFFF, crc = 0x0000;
    uint32_t i = 0;

    for (i = 0; i < length; i++) {
        cal_crc ^= (uint16_t) buffer[i];
        for (int bit = 8; bit > 0; --bit) {
            if ((cal_crc & 0x0001) == 0x0001) {
            	cal_crc = (unsigned short)((cal_crc >> 1) ^ 0x8408);
            }
            else {
            	cal_crc >>= 1;
            }
        }
    }
    cal_crc ^= 0xFFFF;

    crc = ((cal_crc & 0xFF) << 8) | ((cal_crc >> 8) & 0xFF);

    *crcSecond = (uint8_t) crc;
    crc = crc >> 8;
    *crcFirst = (uint8_t) crc;
}

uint8_t gen_resp_packet_PCB(){
	uint8_t tx_PCB, block_type;

	block_type = get_block_type();

	/* Block types are determined by the PCB byte of the block, as described in the ISO IEC 7816-3 document. */
	switch (block_type){
	case S_BLOCK:
		tx_PCB = rx_packet.PCB | 0b00100000 ;
		break;
	case R_BLOCK:
		tx_PCB = 0xe0;
		break;
	case I_BLOCK:
		tx_PCB = rx_packet.PCB ^ 0b1;
		break;
	default:
		tx_PCB = 0;
	}
	return tx_PCB;
}

uint8_t get_block_type(){
	uint8_t block_type;

	if ((rx_packet.PCB & 0b10000000) == 0b00000000){
		block_type = I_BLOCK;
	}
	else if ((rx_packet.PCB & 0b11000000) == 0b10000000){
		block_type = R_BLOCK;
	}
	else if ((rx_packet.PCB & 0b11000000) == 0b11000000){
		block_type = S_BLOCK;
	}
	else{
		block_type = -1; /* Error: not a valid block type! */
	}

	return block_type;
}

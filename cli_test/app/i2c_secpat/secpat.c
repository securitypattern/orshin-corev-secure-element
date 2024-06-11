/* Standard includes. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "libs/utils/include/dbg_uart.h"
#include "libs/cli/include/cli.h"
#include "drivers/include/udma_i2cm_driver.h"
#include "semphr.h"	// Required for configASSERT
#include "libs/utils/include/dbg_uart.h"
#include "hal/include/hal_apb_i2cs_reg_defs.h"
#include "hal/include/hal_apb_i2cs.h"
/* Priorities used by the tasks. */
#define main_TASK_PRIORITY (tskIDLE_PRIORITY + 2)
#define QUEUE_FULL 0x7
extern void vToggleLED(void);

#include "../include/slave_T1_def.h"

/*-----------------------------------------------------------*/
const TickType_t xDelay = 2000 / portTICK_PERIOD_MS;

int bytes_read = 0;

extern packet_t rx_packet; /* Packet received from the master. */
extern packet_t tx_packet; /* Packet to be sent to the master. */

uint8_t clean_queue[128];
uint8_t out_buffer[256] = { 0 };

void send_to_outbound_queue(uint8_t *data, size_t len) {
	for (uint8_t i = 0; i < len; ++i) {
		while (hal_get_i2cs_fifo_apb_i2c_write_flags() == QUEUE_FULL) {
			//FIFO is not full, at least one byte space is available to write into the FIFO,
			//vTaskDelay(3000 * portTICK_PERIOD_MS);
			//CLI_printf("Queue full!\n");
			;
		}
		hal_set_i2cs_fifo_apb_i2c_write_data_port(data[i]);
	}

}

void secpat_i2c_receive(void *pvParameters) {

	CLI_printf("############ SecPat Receive ############\n");
	uint8_t data = '\0';
	for (uint8_t i = 0; i < 128; ++i) {
		clean_queue[i] = i;
	}
	//send_to_outbound_queue(clean_queue, 48);
	CLI_printf("Queue cleaned, reading input...\n");

	for (;;) {

		if (hal_get_i2cs_fifo_i2c_apb_read_flags() != 0) {

			data = hal_get_i2cs_fifo_i2c_apb_read_data_port();

			switch (bytes_read) {
			case 0:
				rx_packet.NAD = data;
				++bytes_read;
				//CLI_printf("NAD: 0x%x\n", data);
				break;
			case 1:
				rx_packet.PCB = data;
				//CLI_printf("PCB: 0x%x\n", data);
				++bytes_read;
				break;
			case 2:
				rx_packet.LEN = data;
				//CLI_printf("LEN: 0x%x\n", data);
				++bytes_read;
				break;
			default:
				if (bytes_read == rx_packet.LEN + T1_HEADER_LEN) {
					rx_packet.CRC_B1 = data;
					//CLI_printf("CRC_B1: 0x%x\n", data);
					++bytes_read;
				} else if (bytes_read == rx_packet.LEN + T1_HEADER_LEN + 1) {
					rx_packet.CRC_B2 = data;
					//CLI_printf("CRC_B2: 0x%x\n", data);
					//We're done!
					CLI_printf("Parsing packet!\n");

					T1_construct_resp_packet_data();
					CLI_printf("Constructed response packet data\n");

					T1_generate_response(out_buffer);
					CLI_printf("Generated response\n");

					send_to_outbound_queue(out_buffer, tx_packet.LEN + 5);
					CLI_printf(
							"Response sent!\nNAD: 0x%x, PCB: 0x%x LEN: 0x%x CRC_B1: 0x%x, CRC_B2: 0x%x\n\n",
							tx_packet.NAD, tx_packet.PCB, tx_packet.LEN,
							tx_packet.CRC_B1, tx_packet.CRC_B2);
					bytes_read = 0;
					memset(&tx_packet, 0, sizeof(tx_packet));
					memset(&rx_packet, 0, sizeof(rx_packet));

				} else {
					rx_packet.APDU_message[bytes_read - T1_HEADER_LEN] = data;
					//CLI_printf("Data %d: 0x%x\n", bytes_read - T1_HEADER_LEN, data);
					++bytes_read;
				}
				break;
			}
		}

	}
}

/*
 void secpat_i2c_send(void *pvParameters) {
 vTaskDelay(xDelay);

 CLI_printf("############ SecPat Send ############\n");

 for (;;) {
 vTaskDelay(xDelay);
 send_to_outbound_queue(hello_from_corev, 19);
 }
 }
 */
//vToggleLED();
//CLI_printf("LED[%d]!\n", i++);
//vTaskDelay(xDelay);
/*
 // Read single byte
 if (hal_get_i2cs_msg_i2c_apb_status() == 1) {
 CLI_printf("Received 0x%x\n", hal_get_i2cs_msg_i2c_apb());
 //When the Message register (offset 0x10) has been read by the APB interface, this bit will be automatically cleared.
 //Checking this condition
 if (hal_get_i2cs_msg_i2c_apb_status() == 0) {
 CLI_printf("Message read and status cleared\n");
 }
 }
 */

/*-----------------------------------------------------------*/

/*
 * Copyright (c) 2024-2025, Security Pattern srl. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/slave_T1_def.h"

#define MAX_DATA_TXRX_LEN 255


uint8_t RxData[MAX_DATA_TXRX_LEN] = {0}; /* Buffer to store the received data. */
uint8_t TxData[MAX_DATA_TXRX_LEN] = {0}; /* Buffer to store the data to be transmitted. */

uint8_t rx_offset = 0; /* Index of the received byte. */
uint8_t tx_offset = 0; /* Index of the byte to be transmitted. */

bool_t isTrue_slave_receiving = FALSE; /* Indicates the direction of the interaction. */

//volatile unsigned long t1; /* For time measurement. */
//volatile unsigned long t2; /* For time measurement. */
//volatile unsigned long diff; /* For time measurement. */


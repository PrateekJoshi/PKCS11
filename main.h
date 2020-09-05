/*
 * main.h
 *
 *  Created on: 03-Nov-2018
 *      Author: 10050746
 */

#ifndef MAIN_H_
#define MAIN_H_

#define AES_IV_LEN 16

/* Function prototypes */
int read_pin(unsigned char *pin,unsigned int *pin_len);
void display_opened_session();

#endif /* MAIN_H_ */

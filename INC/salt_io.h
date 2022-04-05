/* 
 * @file salt_io.h
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating time stamps 
 * in the Salt channelv2 protocol 
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Create Date- 30.12.2021 
 * KEMT FEI TUKE, Diploma thesis
 */

#ifndef SALT_IO_H
#define SALT_IO_H

#include "salt.h"

salt_ret_t my_write(salt_io_channel_t *p_wchannel);
salt_ret_t my_read(salt_io_channel_t *p_rchannel);

salt_time_t my_time;

#endif /* SALT_IO_H */
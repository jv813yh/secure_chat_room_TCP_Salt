/*
* tcp_salt.h   v.0.6
* 
* KEMT FEI TUKE, Diploma thesis
*
* Functions required to deploy the Salt channelv2 protocol on
* the TCP communication channel + auxiliary functions for work
*    
* Windows/Linux
*
* Author-Jozef Vendel  Create date- 16.12.2021 
*/


#ifndef TCP_SALT_CHAT_ROOM_H
#define TCP_SALT_CHAT_ROOM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Libraries of Salt channelv2 */
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

#if defined(_WIN32)
#include <conio.h>
#endif

/* Maximum size of data processed by the program */
#define MAX_SIZE                            UINT16_MAX * 10	

#define AUXILIARY_FIELD_SIZE			 1024
#define STATIC_ARRAY	  				 1024
#define PROTOCOL_BUFFER				 128

/** 
* Delay attack protection, 
* threshold for differense in milliseconds. 
*/
#define TRESHOLD              			  3000
#define TREHOLD_SERVER				  20000

#define TIMEOUT_TV_USEC	  			  100000	

/* Client structure and new data type CLIENT */
typedef struct client {
    uint32_t count_of_messages;
    char address_buffer[100];
    SOCKET sock_fd;
    salt_channel_t channel;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    struct client *p_next;
    struct client *p_previous;
} CLIENT; 

/* LIST structure and new data type LIST */
typedef struct {
    int count;
    CLIENT *p_head;
    CLIENT *p_tail;
} LIST; 

/* ====== Functions for work with database(list) ======= */

/* 
 * Function that allocates memory for the list structure and            *  sets the head and tail to NULL
 *
 *  @return new create list
 */
LIST *create_list();

/* Function for realese LIST */
void realese_list(LIST *p_list);

/* 
 * Function for create client 
 *
 * @return new create client
 */
CLIENT *create_client();

/*
 * Function for delete node(client)
 *
 * @return client for delete
 */
CLIENT * deleteNode(CLIENT * head, SOCKET sock_fd);

/*
 * Function for release client from LIST
 */
void realese_client(LIST *p_list,CLIENT *p_client);

/*
 * Function for connecting a new node(client) to the list
 */
void  insert(LIST *p_list, 
            CLIENT *p_client);

/*
 * Function for listing of clients to the console
 */
void listing_clients(LIST *p_list);

/*
 * Function for client search in the LIST
 *
 * @return found client or NULL
 */ 
CLIENT  *search_client(LIST *p_list,
                       SOCKET y);

/* ====== Functions for work sockets (TCP)   ======= */

/* 
 * Create a socket with which the client will connect to the       * server.
 * Function parameters are arguments from the command line.
 *
 * @par ip_server: ip adrress server 
 * @par port: number of port
 *
 * return client socket with connection to the server in case   * success
 * return wrong report in case failure
 */
SOCKET create_socket_and_connect(const char* ip_server, const char *port);

/* 
 * Creates a socket (return this socket) and expects 
 * a connection from the client.
 * Function parameters are arguments from the command line.
 *
 * @par port: number of port
 *
 * return server socket and expects a connection from the client.
 * return wrong report in case failure
 */
SOCKET create_socket_and_listen(const char *port);

/* ====== Functions for work with reading/writting  ======= */

/* 
 * Function for writing small messages secured and sent by the protocol.
 *
 * @par p_channel:       	pointer to salt_channel_t structure
 * @par p_data:            	message
 * @par size_data,:             size of message
 * @par size_buffer             size of buffer for encryption
 *
 * @return 1          		in case success
 */
uint32_t salt_write_small_messages(salt_channel_t *p_channel,
                            	   uint8_t *p_data,
                            	   uint32_t size_data,
                            	   uint32_t size_buffer);

/* 
 * Function for data receiving, decryption, verify and
 * read them (in Salt channel) for client and server.
 *
 * @par p_channel:       pointer to salt_channel_t structure
 * @par p_buffer:        buffer for encryption
 * @par size_buffer:     size of buffer
 * @par p_msg:           pointer to salt_msg_t structure
 * @par print_out:       if you want to list of receive data -> 1
 *                       or no -> 0
 *
 * @return SALT_SUCCESS          in case success
 * @return SALT_ERROR
 * @return SALT_PENDING
 */
salt_ret_t salt_read_and_decrypt(salt_channel_t *p_channel,
                                uint8_t *p_buffer,
                                uint32_t size_buffer,
                                salt_msg_t *p_msg,
                                uint8_t *p_coppy_buffer,
                                uint32_t *p_decrypt_size,
                                int32_t print_out);

/* = Implementation protocol,handshake and works with data == */

/* 
 * Function solves the client's communication with the server and implementation protocol and also salt handshake
 *
 * @par p_socket_peer1:   socket of clients, after successfuly TCP handshake
 */

void connection_and_writting(SOCKET *p_socket_peer1);


/* 
 * Function for create Salt handshake between server-client
 * (uses server)
 *
 * @parameter: p_client	socket obtained after TCP handshake from client
 */
void salt_hndshk(CLIENT *p_client);

/*
 * Function for handling the entire chat service of the server 
 * 
 * @parameter: socket_listen	socket of server
 *
 * @return 1			     in case of success
*/
uint32_t salt_chat_room_service(SOCKET socket_listen); 

#endif

/*
 * client00.c    v.0.0
 *
 * 	  CLIENT
 *
 * Deployment of Salt-Channelv2 cryptographic network protocol on TCP communication channel in TCP / IP models.
 * 
 * Windows 10 Home operating system, compiled under the MinGW-w64 tool.
 *
 * Author-Jozef Vendel  Date- 21.4.2021 
 * ===============================================
 */

//Libraries for working with network tools in Windows
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

//pragma comment not needed because I use the Makefile file flag -lws2_32
//#pragma comment(lib, "ws2_32.lib")

//Constants for working with sockets in Windows
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

//Libraries of Salt channelv2
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"
#if defined(_WIN32)
#include <conio.h>
#endif

//Field listing function
#define HEXDUMPv2(data, size) hexdumpv2(data, size)

//Function for unwrapping and decrypting messages
salt_ret_t salt_read_begin_pom(salt_channel_t *p_channel, 
							   uint8_t *p_buffer, 
							   uint32_t buffer_size, 
							   salt_msg_t *p_msg);

void connection_and_writting(SOCKET *context);

int main(int argc, char *argv[]) {

#if defined(_WIN32)

    //The MAKEWORD macro allows us to request Winsock version 2.2
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }

    //Input from the command line
    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        return 1;
    }

    //We use getaddrinfo() to fill in a struct addrinfo structure with the needed information
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(argv[1], argv[2], &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //We use getnameinfo() to convert the address back into a string because we want print it out
    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);
    printf("%s %s\n", address_buffer, service_buffer);

    //Creating socket 
    printf("Creating socket...\n");
    SOCKET socket_peer = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //After the socket has been created, we call connect() to establish a connection to the remote server
    printf("Connecting...\n");
    if (connect(socket_peer,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //After we've called connect() with peer_address, we use the freeaddrinfo() function to free the memory for peer_address
    freeaddrinfo(peer_address);


    printf("Connected.\n");
    printf("TCP was successfully performed...\n\nCreating Salt hanshake...\n");

    //Function for establishing a connection using the handshake process and exchanging data 
    //with the server
    connection_and_writting(&socket_peer);


    printf("Closing socket...\n");
    CLOSESOCKET(socket_peer);

    //Closing Winsock
    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}

void connection_and_writting(SOCKET *socket_peer1) 
{

//Variables
salt_channel_t client_channel;
salt_ret_t ret, ret_msg;
salt_msg_t msg_out, msg_in;

uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
uint8_t tx_buffer[SALT_HNDSHK_BUFFER_SIZE];
uint8_t rx_buffer[SALT_HNDSHK_BUFFER_SIZE];
uint32_t verify = 0, msg_size = 0, head = 0;
char input[SALT_HNDSHK_BUFFER_SIZE];
clock_t start_t, end_t;

SOCKET socket_peer = *socket_peer1;

//Create Salt channel client
ret = salt_create(&client_channel, SALT_CLIENT, my_write, my_read, &my_time);
assert(ret == SALT_SUCCESS);

//Creating pairs of signature keys
ret = salt_create_signature(&client_channel); 
assert(ret == SALT_SUCCESS);

//Setting up other necessary cryptographic operations to use the protocol properly
ret = salt_init_session(&client_channel, hndsk_buffer, sizeof(hndsk_buffer));
assert(ret == SALT_SUCCESS);

//Setting up socket with function for read messages and write messages
ret = salt_set_context(&client_channel, &socket_peer, &socket_peer);
assert(ret == SALT_SUCCESS);

//Setting up delay treshold 
salt_set_delay_threshold(&client_channel, 1000);

//Creating Salt handshake
do {
    start_t = clock();
    ret = salt_handshake(&client_channel, NULL);
    end_t = clock();
    if (ret == SALT_ERROR) {
        printf("Salt error: 0x%02x\r\n", client_channel.err_code);
        printf("Salt error read: 0x%02x\r\n", client_channel.read_channel.err_code);
        printf("Salt error write: 0x%02x\r\n", client_channel.write_channel.err_code);
        assert(ret != SALT_ERROR);
    } else if (ret == SALT_SUCCESS) {
            printf("\nSalt handshake successful\r\n");
            printf("\n");
            printf("\t\n***** CLIENT:Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                    start_t) / (CLOCKS_PER_SEC))); 
            printf("\n");
            verify = 1;
    }
    } while (ret == SALT_PENDING);

     //If the handshake was successful, we can proceed with the data exchange
while(verify){

   	fd_set reads;
    FD_ZERO(&reads);
    FD_SET(socket_peer, &reads);
#if !defined(_WIN32)
    FD_SET(0, &reads);
#endif

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;

    if (select(socket_peer+1, &reads, 0, 0, &timeout) < 0) {
        fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    if (FD_ISSET(socket_peer, &reads)){
        //Receiving encrypted messages, unwrapping, decrypting
        memset(rx_buffer, 0, sizeof(hndsk_buffer));
        ret_msg = salt_read_begin_pom(&client_channel, rx_buffer, sizeof(rx_buffer), &msg_in);
        
        if(ret_msg == SALT_ERROR) {
            printf("Failed to dencrypt or receive message from server\n");
            break;
        }
    }

//#if defined(_WIN32)
    if(_kbhit()) {
//#else
        //if(FD_ISSET(0, &reads)) {
//#endif
    	ret_msg = SALT_ERROR;
    	memset(tx_buffer, 0, sizeof(hndsk_buffer));

    	//Inputting clear text from CL from client
        //printf("\nEnter message:\n");
        if (!fgets(input, SALT_HNDSHK_BUFFER_SIZE, stdin)) break;

        // printf("\n");
        msg_size = strlen(input);
        //msg_size = --msg_size;

        //Prepare the message before encrypting and sending 
        salt_write_begin(tx_buffer, sizeof(tx_buffer), &msg_out);

        //Copy clear text message to be encrypted to next encrypted package
        salt_write_next(&msg_out, (uint8_t *)input, msg_size);

        //Wrapping and creating encrypted messages, sending for server 
        ret_msg = salt_write_execute(&client_channel, &msg_out, false);

        if(ret_msg == SALT_ERROR) {
            printf("Failed to encrypt or send message from client\n");
            break;
           }
        }
    }

}


//Receiving encrypted messages, unwrapping, decrypting
salt_ret_t salt_read_begin_pom(salt_channel_t *p_channel, 
							   uint8_t *p_buffer, 
							   uint32_t buffer_size, 
							   salt_msg_t *p_msg)
{
    
    salt_ret_t ret;
    uint32_t size = buffer_size - 14U;
    uint8_t *header;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    //Verification
    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);

    SALT_VERIFY(buffer_size >= SALT_OVERHEAD_SIZE, SALT_ERR_BUFF_TO_SMALL);
    SALT_VERIFY(NULL != p_msg, SALT_ERR_NULL_PTR);

    //Receiving encrypted messages
    ret = salti_io_read(p_channel, &p_buffer[14], &size);

    //If the message was successfully received, the message is decrypted and a clear message is displayed on the screen
    if (SALT_SUCCESS == ret) {

        /*
         * salti_unwrap returns pointer to clear text message to
         * p_buffer and the length of the clear text message to
         * size.
         */

    	//Message is decrypted
    	ret = salti_unwrap(p_channel, p_buffer, size, &header, &p_buffer, &size);

    	//Verification
    	SALT_VERIFY(SALT_SUCCESS == ret, p_channel->err_code);
    	SALT_VERIFY(((SALT_APP_PKG_MSG_HEADER_VALUE == header[0]) ||
                (SALT_MULTI_APP_PKG_MSG_HEADER_VALUE == header[0])) &&
                (header[1] == 0x00U), SALT_ERR_BAD_PROTOCOL);

    	salt_err_t err_code = salt_read_init(header[0], p_buffer, size, p_msg);
    	SALT_VERIFY(err_code == SALT_ERR_NONE, err_code);
      	
      	//Clear message is displayed on the screen
    	printf("\nDecrypted message from client:\n%s\n", p_buffer);
    	printf("\n");
    }
 

    return ret;
}



/*
 * server00.c    v.0.0
 *
 *    SERVER
 *
 * Deployment of Salt-Channelv2 cryptographic network protocol on TCP communication channel in TCP / IP models.
 * 
 * Windows 10 Home operating system, compiled under the MinGW-w64 tool.
 *
 * Author-Jozef Vendel  Date- 09.5.2021 
 * ===============================================
 */

//Libraries for working with network tools in Windows
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

//pragma comment nie je potrebny, lebo vyuzivam v Makefile subore flag -lws2_32
//#pragma comment(lib, "ws2_32.lib")

//Constants for working with sockets in Windows
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

//Libraries of Salt channelv2
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

#include <time.h>

//Function for reads encrypted message
salt_ret_t salt_read_begin_pom(salt_channel_t *p_channel, 
							   uint8_t *p_buffer, 
							   uint32_t buffer_size, 
							   salt_msg_t *p_msg, 
							   uint8_t *p_pom, 
							   uint32_t *p_size);

//Ready sk_sec key for server
static uint8_t host_sk_sec[64] = { 
    0x7a, 0x77, 0x2f, 0xa9, 0x01, 0x4b, 0x42, 0x33,
    0x00, 0x07, 0x6a, 0x2f, 0xf6, 0x46, 0x46, 0x39,
    0x52, 0xf1, 0x41, 0xe2, 0xaa, 0x8d, 0x98, 0x26,
    0x3c, 0x69, 0x0c, 0x0d, 0x72, 0xee, 0xd5, 0x2d,
    0x07, 0xe2, 0x8d, 0x4e, 0xe3, 0x2b, 0xfd, 0xc4,
    0xb0, 0x7d, 0x41, 0xc9, 0x21, 0x93, 0xc0, 0xc2,
    0x5e, 0xe6, 0xb3, 0x09, 0x4c, 0x62, 0x96, 0xf3,
    0x73, 0x41, 0x3b, 0x37, 0x3d, 0x36, 0x16, 0x8b
};

struct clientInfo {
    SOCKET socket_client;
    char ip_addr[16];
    struct sockaddr_in client;
    salt_channel_t channel;
};

int main() { 

#if defined(_WIN32)

    //Variables
    SOCKET socket_listen;;
    salt_channel_t server;

    struct clientInfo *client_info;

    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t rx_buffer[UINT16_MAX * 4];
    uint8_t pom_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t tx_buffer[UINT16_MAX * 4];

    salt_msg_t msg_out;
    salt_ret_t ret;
    salt_ret_t ret_msg;
    salt_msg_t msg_in;

    uint8_t protocol_buffer[128];
    salt_protocols_t protocols;

    clock_t start_t, end_t;
    //uint8_t version[2] = { 0x00, 0x01 };

    uint32_t verify = 0, decrypt_size;

    //The MAKEWORD macro allows us to request Winsock version 2.2
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) { //inicializacia Winscok-u
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
	
    printf("Configuring local address...\n");
    //Struct addrinfo hints
    struct addrinfo hints; 
    memset(&hints, 0, sizeof(hints));
    //Looking address IPv4
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM; //TCP connection
    //We ask getaddrinfo () to set the address, for the availability of any network device
    hints.ai_flags = AI_PASSIVE;

    //Setting a pointer to a structure that contains return information from the getaddrinfo () function
    struct addrinfo *bind_address; 
    getaddrinfo(0, "8080", &hints, &bind_address); //port 8080, generate an address suitable for the bind () function

    //Creating socket
    printf("Creating socket...\n");
    socket_listen = socket(bind_address->ai_family, 
            bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //Binding socket to local address
    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
                bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //After we've called bind(), we use the freeaddrinfo() function to free the memory for bind_address
    freeaddrinfo(bind_address); 
    puts("Bind done");

    printf("Listening...\n");
    if (listen(socket_listen, 10) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //Define fd_set structure master that stores all of the active sockets 
    fd_set master;
    FD_ZERO(&master);
    FD_SET(socket_listen, &master);
    SOCKET max_socket = socket_listen;

    printf("Waiting for connections...\n");

    while(1) {

        fd_set reads;
        reads = master;

        //The select function determines the status of one or more sockets, waiting if necessary, to perform synchronous I/O
        if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }

        SOCKET i;

        //Loop through each possible socket 
        for(i = 1; i <= max_socket; ++i) {
            if (FD_ISSET(i, &reads)) {

                //If socket_listen, create TCP connection of accept() function
                if (i == socket_listen) {
                	
                    struct sockaddr_storage client_address;
                    socklen_t client_len = sizeof(client_address);
                    client_info = malloc(sizeof(struct clientInfo));

                    client_info->socket_client = accept(socket_listen,
                            (struct sockaddr*) &client_address,
                            &client_len);
                    if (!ISVALIDSOCKET(client_info->socket_client)) {
                        fprintf(stderr, "accept() failed. (%d)\n",
                                GETSOCKETERRNO());
                        return 1;
                    }
                    
                    //Addition socket_client to the fd_set structure master
                    FD_SET(client_info->socket_client, &master);
                    if (client_info->socket_client > max_socket)
                        max_socket = client_info->socket_client;
                
                    char address_buffer[100];

                    //Prints the client address using the getnameinfo() function
                    getnameinfo((struct sockaddr*)&client_address,
                            client_len,
                            address_buffer, sizeof(address_buffer), 0, 0,
                            NI_NUMERICHOST);
                    printf("New connection from %s\n", address_buffer);
                    
                    printf("\nWaiting for succeses Salt handshake...\n");
                    
                    //Creates a new salt channel
                    ret = salt_create(&server, SALT_SERVER, my_write, my_read, &my_time);
                    assert(ret == SALT_SUCCESS);

                    //Initiates to add information about supported protocols to host
                    ret = salt_protocols_init(&server, &protocols, protocol_buffer, sizeof(protocol_buffer));
                    assert(ret == SALT_SUCCESS);

                    //Add a protocol to supported protocols
                    ret = salt_protocols_append(&protocols, "ECHO", 4);
                    assert(ret == SALT_SUCCESS);

                    //Sets the signature used for the salt channel
                    ret = salt_set_signature(&server, host_sk_sec);
                    assert(ret == SALT_SUCCESS);

                    //New ephemeral key pair is generated and the read and write nonce  is reseted
                    ret = salt_init_session(&server, hndsk_buffer, sizeof(hndsk_buffer));
                    assert(ret == SALT_SUCCESS);

                    //Sets the context passed to the user injected read implementation
                    ret = salt_set_context(&server, &client_info->socket_client, &client_info->socket_client);
                    assert(ret == SALT_SUCCESS);

                    //Set threshold for delay protection
                    salt_set_delay_threshold(&server, 20000);

                    start_t = clock();
                    //Salt handshake 
                    ret = salt_handshake(&server, NULL);
                    end_t = clock();

                    printf("\n");
                    printf("\t\n***** SERVER:Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
                            start_t) / (CLOCKS_PER_SEC))); 
                    printf("\n");

                    //Testing success for Salt handshake
                    while (ret != SALT_SUCCESS) {

                        if (ret == SALT_ERROR) {
                        printf("Error during handshake:\r\n");
                        printf("Salt error: 0x%02x\r\n", server.err_code);
                        printf("Salt error read: 0x%02x\r\n", server.read_channel.err_code);
                        printf("Salt error write: 0x%02x\r\n", server.write_channel.err_code);

                        printf("Connection closed.\r\n");
                        CLOSESOCKET(client_info->socket_client);
           
                        break;
                        }

                    ret = salt_handshake(&server, NULL);
                    }
                    if (ret == SALT_SUCCESS) {
                        printf("\nSalt handshake successful\r\n");
                        printf("\n");
                        verify = 1;
                    }

                    } else if (verify){

                        ret_msg = SALT_ERROR;
                        memset(rx_buffer, 0, sizeof(hndsk_buffer));

                        //Reads encrypted message
                        ret_msg = salt_read_begin_pom(&server, rx_buffer, sizeof(rx_buffer), &msg_in, pom_buffer, &decrypt_size);

                        SOCKET j;
                        if (ret_msg == SALT_SUCCESS){ 
                        	for (j = 1; j <= max_socket; ++j){
                        		if (FD_ISSET(j, &master)){
                        			if (j == socket_listen || j == i)
                                		continue;
                            		else { 

	 									//Prepare data before send
                            			salt_write_begin(tx_buffer, sizeof(tx_buffer), &msg_out);

                            			//Copy clear text message to be encrypted to next encrypted package
                            			salt_write_next(&msg_out, (uint8_t * )pom_buffer, decrypt_size);

                            			//Wrapping, creating encrpted messages
                            			salt_write_execute(&server, &msg_out, false);
                            		} 
                        		}
                        	}
                        } 

                        while (ret_msg == SALT_ERROR){
                            printf("\nThe message could not be decrypted\nClosing the socket\n");
                            CLOSESOCKET(client_info->socket_client);
                            break;
                        } //Testing Salt error of messages
                    } //Exchange of secured data
            } //if FD_ISSET
        } //for i to max_socket
    } //while(1)
    
    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}

//Function for reads encrypted message
salt_ret_t salt_read_begin_pom(salt_channel_t *p_channel, 
							   uint8_t *p_buffer, 
							   uint32_t buffer_size, 
							   salt_msg_t *p_msg, 
							   uint8_t *p_pom, 
							   uint32_t *p_size)
{
    
    salt_ret_t ret;
    uint32_t size = buffer_size - 14U;
    uint8_t *header;

    if (NULL == p_channel) {
        return SALT_ERROR;
    }

    SALT_VERIFY(SALT_SESSION_ESTABLISHED == p_channel->state,
                SALT_ERR_INVALID_STATE);

    SALT_VERIFY(buffer_size >= SALT_OVERHEAD_SIZE, SALT_ERR_BUFF_TO_SMALL);
    SALT_VERIFY(NULL != p_msg, SALT_ERR_NULL_PTR);

    ret = salti_io_read(p_channel, &p_buffer[14], &size);

    if (SALT_SUCCESS == ret) {

    /*
     * salti_unwrap returns pointer to clear text message to
     * p_buffer and the length of the clear text message to
     * size.
     */

    ret = salti_unwrap(p_channel, p_buffer, size, &header, &p_buffer, &size);
   
    SALT_VERIFY(SALT_SUCCESS == ret, p_channel->err_code);
    SALT_VERIFY(((SALT_APP_PKG_MSG_HEADER_VALUE == header[0]) ||
                (SALT_MULTI_APP_PKG_MSG_HEADER_VALUE == header[0])) &&
                (header[1] == 0x00U), SALT_ERR_BAD_PROTOCOL);

    salt_err_t err_code = salt_read_init(header[0], p_buffer, size, p_msg);
    SALT_VERIFY(err_code == SALT_ERR_NONE, err_code);

    *p_size = size;
    memcpy(p_pom, p_buffer, *p_size);
      
    printf("\nDecrypted message from client:\n%s\n", p_buffer);
    printf("\n");

    } else printf("Failed to load message\n");

    return ret;
}



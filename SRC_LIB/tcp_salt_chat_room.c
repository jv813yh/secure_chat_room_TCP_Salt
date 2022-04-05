/**
 * ===============================================
 * tcp_salt.c   v.1.1
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * Created support functions for deploying 
 * Salt channel protocol on TCP/IP for chat room
 *
 * Windows/Linux
 *
 * Author-Jozef Vendel  Create date- 16.12.2021 
 * ===============================================
 */

/* ======== Includes ================================ */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

/* ===== Salt-channel libraries ===== */
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

#if defined(_WIN32)
#include <conio.h>
#endif

/* Macros for networking work Windows/Linux */
#include "win_linux_sockets.h"

/*
 * Implementation of functions and macros for chat room
 * service provided by Salt channel protocol
 */
#include "tcp_salt_chat_room.h"

/* ========== Ready sk_sec_key for server ======== */
#include "server_sk_key.h"


/* ======================== Functions for socket and working with it  =========================== */

SOCKET create_socket_and_connect(const char* ip_server, const char *port) 
{
    printf("\nConfiguring remote address...\n");

    /*
     * We use getaddrinfo() to fill in a 
     * struct addrinfo structure with the needed information
     */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *peer_address;
    
    if (getaddrinfo(ip_server, port, &hints, &peer_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /*
     * We use getnameinfo() to convert the address back into a string 
     * because we want print it out
     */
    printf("Remote address is: ");
    char address_buffer[AUXILIARY_FIELD_SIZE];
    char service_buffer[AUXILIARY_FIELD_SIZE];

    int return_getnameinfo;
    return_getnameinfo = getnameinfo(peer_address->ai_addr, 
            peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);

    if (return_getnameinfo)
    {
        fprintf(stderr, "getnameinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }
    printf("%s %s\n", address_buffer, service_buffer);

    /* Creating client socket - client_socket */
    printf("\nCreating client socket...\n");
    SOCKET client_socket;
    client_socket = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(client_socket)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /* 
     * After the socket has been created, we call connect() 
     * to establish a connection to the remote server
     */
    printf("Connecting...\n");
    if (connect(client_socket,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /*
     * After we've called connect() with peer_address, 
     * we use the freeaddrinfo() function to free the memory for peer_address
     */
    freeaddrinfo(peer_address);

    return client_socket;
}

SOCKET create_socket_and_listen(const char* host, const char *port) 
{
    printf("\nConfiguring local address...\n");

    /* 
     * Configuring remote address with getaddrinfo - 
     * the parameters were entered from the command line 
     * like ip address and port number 
     */
    /* Struct addrinfo hints */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    /* Looking address IPv4 */
    hints.ai_family = AF_INET;
    /* TCP connection */
    hints.ai_socktype = SOCK_STREAM;
    /* 
     * We ask getaddrinfo () to set the address, 
     * for the availability of any network device
     */
    hints.ai_flags = AI_PASSIVE;

    /* 
     * Setting a pointer to a structure that contains return 
     * information from the getaddrinfo () function
     */
    struct addrinfo *bind_address;
    /*
     * for example port 8080, generate an address suitable for the bind () function
     * IPVv4 and port from CLI
     */
    if (getaddrinfo(host, port, &hints, &bind_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    /* Creating server socket - socket_listen */
    printf("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
            bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    /* Binding socket to local address */
    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
                bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    /*
     * After we've called bind(), we use the freeaddrinfo() 
     * function to free the memory for bind_address
     */
    puts("Bind done\n");
    freeaddrinfo(bind_address);

    /* The server is waiting for a client connection attempt */
    printf("Listening...\n\n");
    if (listen(socket_listen, 10) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    return socket_listen;
}

/* ======================== Functions for protocol implementation and handshake creation  =========================== */

//Function for create Salt handshake (uses a server)
void salt_hndshk(CLIENT *p_client)
{
    /* hndsk_buffer: buffer for performing Salt handshake */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];

    /* 
     * protocol buffer: Supported protocol of salt-channel. 
     * The user support what protocols is used by the
     * salt-channel.
     */
    uint8_t protocol_buffer[PROTOCOL_BUFFER];

    salt_protocols_t protocols;
    salt_ret_t ret;

    // Create a new Salt channel 
    ret = salt_create(&p_client->channel, SALT_SERVER, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);

    //Initiates to add information about supported protocols to host
    ret = salt_protocols_init(&p_client->channel, &protocols, protocol_buffer, sizeof(protocol_buffer));
    assert(ret == SALT_SUCCESS);

    //Add a protocol to supported protocols
    ret = salt_protocols_append(&protocols, "ECHO", 4);
    assert(ret == SALT_SUCCESS);

    //Sets the signature used for the salt channel
    ret = salt_set_signature(&p_client->channel, host_sk_sec);
    assert(ret == SALT_SUCCESS);

    //New ephemeral key pair is generated and the read and write nonce  is reseted
    ret = salt_init_session(&p_client->channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    //Sets the context passed to the user injected read implementation
    ret = salt_set_context(&p_client->channel, &p_client->sock_fd, &p_client->sock_fd);
    assert(ret == SALT_SUCCESS);

    //Set threshold for delay protection
    salt_set_delay_threshold(&p_client->channel, TREHOLD_SERVER);

    printf("The implementation of the Salt channel protocol was successful\n");

    //Salt handshake 
    ret = salt_handshake(&p_client->channel, NULL);

    //Testing success for Salt handshake
    while (ret != SALT_SUCCESS) 
    {
        if (ret == SALT_ERROR) 
        {
            printf("Error during handshake:\r\n");
            printf("Salt error: 0x%02x\r\n", p_client->channel.err_code);
            printf("Salt error read: 0x%02x\r\n", p_client->channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", p_client->channel.write_channel.err_code);
            printf("Connection closed.\r\n");

            CLOSESOCKET(p_client->sock_fd);

            break;
        }

        ret = salt_handshake(&p_client->channel, NULL);
    }

    if (ret == SALT_SUCCESS) printf("\nSalt handshake successful\r\n\n");
} 

/* ================ Function also solves the client's communication with the server =============== */

void connection_and_writting(SOCKET *p_socket_peer1) 
{

    /* Variables */
    salt_channel_t client_channel; /*<- pointer to salt_channel_t structure */
    salt_ret_t ret;                /*<- pointer to salt_msg_t structure */
    salt_msg_t msg_in;             /*<- return value of protocol,
                                    *   typedef enum
                                    *   which can obtain values:
                                    *   SALT_SUCCESS, SALT_PENDING, SALT_ERROR  
                                    */

    /* Buffer for performing a Salt handshake of size SALT_HNDSHK_BUFFER_SIZE */
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];

    /*
     * rx_buffer: buffer for receiving and decryption of data
     * input:     input data from client
     */
    uint8_t rx_buffer[MAX_SIZE], input[MAX_SIZE];

    /*
     * msg_size:      size of data
     * send_messages: check return value of encryption data
     * repeat:        if you want to leave
     */
    uint32_t msg_size = 0, send_messages, repeat;

    SOCKET socket_peer = *p_socket_peer1;

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
    salt_set_delay_threshold(&client_channel, TRESHOLD);

    printf("The implementation of the Salt channel protocol was successful\n");

    //Creating Salt handshake
    do {
        ret = salt_handshake(&client_channel, NULL);
        if (ret == SALT_ERROR) 
        {
            printf("Salt error: 0x%02x\r\n", client_channel.err_code);
            printf("Salt error read: 0x%02x\r\n", client_channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", client_channel.write_channel.err_code);
            assert(ret != SALT_ERROR);
        } else if (ret == SALT_SUCCESS) printf("\nSalt handshake successful\r\n\n\n");
    } while (ret == SALT_PENDING);

    //If the Salt handshake was successful, we can proceed with the data exchange

/* ========== Sending and receiving secured data =========== */
    while(ret == SALT_SUCCESS)
    {   
        /* 
         * Structure fd_set for select() by which I know which sockets 
         * are ready for processing
         */
        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(socket_peer, &reads);
#if !defined(_WIN32)
        FD_SET(0, &reads);
#endif
        /* Setting the time dependence of sockets */
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = TIMEOUT_TV_USEC;

        /* Search for active sockets */
        if (select(socket_peer+1, &reads, 0, 0, &timeout) < 0) 
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());

        /* Sockets ready to read */
        if (FD_ISSET(socket_peer, &reads))
        {
            ret = SALT_ERROR;

            //Receiving encrypted messages, unwrapping, decrypting and listing it
            ret = salt_read_and_decrypt(&client_channel, 
                                        rx_buffer, 
                                        sizeof(rx_buffer), 
                                        &msg_in, 
                                        NULL, 
                                        0,
                                        1);
            assert(ret == SALT_SUCCESS);
        }

        /* Receiving data from the CLI */
#if defined(_WIN32)
        if(_kbhit())
        {
#else
        if(FD_ISSET(0, &reads)) 
        {
#endif
            memset(input, 0, MAX_SIZE);
            
            /* Inputting clear text from CL from client */
            if (!fgets((char *)input, MAX_SIZE, stdin)) break;
            /* Size of message */
            msg_size = strlen((char *)input);

            /* Buffer preparation, encryption and messaging */
            send_messages = salt_write_small_messages(&client_channel, 
                                                      input, 
                                                      msg_size, 
                                                      MAX_SIZE);
            if (send_messages != 1) printf("Failed to encrypt or send message from server");
            else printf("\n******| Encrypting data and sending it with Salt channel |********\n");

            /* End of sending and receiving data, encryption and decryption */ 
            printf("\nDo you want to finish?\nPress number, '1'-> to quit\n"
                "Press '0' -> to continue\n");
            if (EOF == scanf("%d", &repeat))
            {
                printf("Error processing termination request\n");
                break;
            }

            /* Buffer cleaning */ 
            while (getchar() != '\n')
                ;

            /* Termination of client-server communication */
            if(repeat) break;
            printf("\n");
        }
    }
}

/* ===================== Functions for reading and writing messages ======================== */

salt_ret_t salt_read_and_decrypt(salt_channel_t *p_channel,
                                uint8_t *p_buffer,
                                uint32_t size_buffer,
                                salt_msg_t *p_msg,
                                uint8_t *p_coppy_buffer,
                                uint32_t *p_decrypt_size,
                                int32_t print_out)
{
    /*
     * typedef enum
     * which can obtain values:
     * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
     */
    salt_ret_t ret_msg;

    printf("\n******| Data reception and decryption with Salt channel |********\n");

    /**
    * Reads one or multiple encrypted message.
    *
    * The actual I/O operation of the read process.
    *
    * @param p_channel:
    * Pointer to salt channel handle.
    * @param p_buffer:      
    * Pointer where to store received (clear text) data.
    * @param size_buffer:   
    * Size of p_buffer, must be greater or equal to SALT_READ_OVERHEAD_SIZE.
    * @param p_msg:         
    * Pointer to message structure to use when reading the message.
    *
    *
    * @return SALT_SUCCESS A message was successfully received.
    * @return SALT_PENDING The receive process is still pending.
    * @return SALT_ERROR   If any error occured during the read. If this occured, the session is considered
    *                      closed and a new handshake must be performed. I.e., the session must be initated
    *                      and then a handshake.
    */

    do 
    {
        ret_msg = salt_read_begin(p_channel, p_buffer, size_buffer, p_msg);
    } while (ret_msg == SALT_PENDING);

    /**
    * Used to read messages recevied.
    *
    * Used to read single or multiple application packages. Due to encryption overhead
    * the longest clear text message that can be received is SALT_READ_OVERHEAD_SIZE smaller
    * than the provided receive buffer.
    *
    * @param p_msg     Pointer to message structure.
    *
    * @return SALT_SUCCESS The next message could be parsed and ready to be read.
    * @return SALT_ERROR   No more messages available.
    *
    * Read message structure:
    * typedef union salt_msg_u {
    *   struct {
    *      uint8_t     *p_buffer;          < Message buffer. 
    *      uint8_t     *p_payload;         < Pointer to current message. 
    *      uint32_t    buffer_size;        < Message buffer size. 
    *      uint32_t    buffer_used;        < Index of how many bytes have been processed. 
    *      uint16_t    messages_left;      < Number of messages left to read. 
    *      uint32_t    message_size;       < Current message size. 
    *   } read;
    * } salt_msg_t;
    * 
    */

    if (ret_msg == SALT_SUCCESS)     
    {   
        printf("\nRecevied %d BLOCK/BLOCKS\n\n", ++p_msg->read.messages_left);

        do 
        {
            if (SALT_CLIENT == p_channel->mode) 
            {
                /* Listing of received data */
                if(print_out)
                    printf("%*.*s\r\n", 0, p_msg->read.message_size, (char*) p_msg->read.p_payload);
            } else if (SALT_SERVER == p_channel->mode) 
            {
                memcpy(&p_coppy_buffer[*p_decrypt_size], p_msg->read.p_payload, p_msg->read.message_size);
                *p_decrypt_size += p_msg->read.message_size;
            }
        } while (salt_read_next(p_msg) == SALT_SUCCESS);
    }

    /* Verification of the decryption and data transmission process */
    if (ret_msg == SALT_ERROR) printf("\nError during reading :(\r\n");

    return ret_msg;
}

uint32_t salt_write_small_messages(salt_channel_t *p_channel,
                                   uint8_t *p_data,
                                   uint32_t size_data,
                                   uint32_t size_buffer)
{

    /* Small buffer for encryption of data */
    uint8_t tx_buffer[size_buffer];

    /* Pointer to the structure for works with data */
    salt_msg_t out_msg;

    /* Return value*/
    salt_ret_t ret;

    /* Prepare the message before encrypting and sending */
    ret = salt_write_begin(tx_buffer, sizeof(tx_buffer), &out_msg);
    assert(ret == SALT_SUCCESS);
   
    /* 
     * Copy clear text message to be encrypted to next encrypted package 
     * Checking the correct parameter settings, selecting the packet type, verification
     */
    ret = salt_write_next(&out_msg, p_data, size_data);
    assert(ret == SALT_SUCCESS);

    /* Wrapping and creating encrypted messages, sending for client */
    ret = salt_write_execute(p_channel, &out_msg, false);
    assert(ret == SALT_SUCCESS);

    return 1;
}

/* ======================= Function for handling the entire chat service of the server ================= */

uint32_t salt_chat_room_service(SOCKET socket_listen) 
{ 
    /*
     * tx_buffer:               buffer for encryption data
     * rx_buffer:               buffer for decryption data
     * pom_buffer:              clear data
     */
    uint8_t tx_buffer[MAX_SIZE], rx_buffer[MAX_SIZE], pom_buffer[MAX_SIZE];

    /*
     * decrypt_size:             the size of the decrypted message   
     * return_getnameinfo:       return value for getnameinfo()
     * ok_list:                  the value will increase if a database for clients
     *                           can be created
     * shut_down:                shutting down the server
     */
    uint32_t decrypt_size, return_getnameinfo, ok_list = 0;
    int32_t shut_down = 1;

    /*
     * msg_in:                   pointer to message strcuture for reading 
     * msg_out:                  pointer to message strcuture for writing
     */
    salt_msg_t msg_in, msg_out;

     /*
      * Return check value for protocol
      *
      * typedef enum
      * which can obtain values:
      * SALT_SUCCESS, SALT_PENDING, SALT_ERROR            
      */
    salt_ret_t ret_msg;
    
/* ==== Creating list(p_list) for storing connected clients and define fd_set structure ==== */

    /* Create an empty list(p_list) */ 
    LIST *p_list = create_list();
    if (p_list != NULL) ok_list++;
    else
    {
        printf("Failed to create database for clients\n");
        return 0;
    }

    /* fd_set structure master that stores all of the active sockets */
    fd_set master;
    FD_ZERO(&master);
    FD_SET(socket_listen, &master);
    SOCKET max_socket = socket_listen;

/* ========== Creating Handshake, Implementation Salt and Salt Handshake ============== */
/* ========== Sending and receiving secured data  in cycle               ============== */
    while(ok_list) 
    {
        fd_set reads;
        reads = master;

        //The select function determines the status of one or more sockets, waiting if necessary, to perform synchronous I/O
        if (select(max_socket+1, &reads, 0, 0, 0) < 0) 
        {
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }

        SOCKET i;
        //Loop through each possible socket 
        for(i = 1; i <= max_socket; ++i) 
        {
            if (FD_ISSET(i, &reads)) 
            {
                /* If socket_listen, create TCP connection of accept() function */
                if (i == socket_listen) 
                {
                    /* Create new data type CLIENT for works with connected client */
                    CLIENT *client_info;

                    /* Creating TCP connection with client */
                    client_info = create_client();
                    client_info->client_len = sizeof(client_info->client_address);
                    client_info->sock_fd = accept(socket_listen,
                            (struct sockaddr*) &client_info->client_address,
                            &client_info->client_len);

                    if (!ISVALIDSOCKET(client_info->sock_fd)) 
                    {
                        fprintf(stderr, "accept() failed. (%d)\n",
                                GETSOCKETERRNO());
                        return 1;
                    }   

                    /* Adding a client socket to the fd_set structure */
                    FD_SET(client_info->sock_fd, &master);
                    if (client_info->sock_fd > max_socket)
                        max_socket = client_info->sock_fd;
                
                    /* Prints the client address using the getnameinfo() function */
                    return_getnameinfo = getnameinfo((struct sockaddr*)&client_info->client_address,
                            client_info->client_len,
                            client_info->address_buffer, 
                            100, 0, 0,
                            NI_NUMERICHOST);
                    if (return_getnameinfo)
                    {
                        fprintf(stderr, "getnameinfo() failed. (%d)\n", GETSOCKETERRNO());
                        return 1;
                    }
                    printf("New connection %s\n", client_info->address_buffer);

                    /*
                     * TCP connection was successfully established in the 
                     * client-server architecture.
                     *
                     * Now, We can implementation Salt protocol and perform Salt handshake
                     */
                    
                    printf("\nWaiting for success Salt handshake ...\n");

                    /* This functions are type of void */
/* =========== Implementation Salt protocol and performing Salt handshake ============== */
                    salt_hndshk(client_info);
                    client_info->count_of_messages = 0;

/* =========== Insert client to the list of clients ==================================== */
                    insert(p_list, client_info);

                    /* List of clients connected to the server with a successful Salt handshake */      
                    listing_clients(p_list);
 
                } else 
                {

                    /* Cleaning the necessary variables */
                    memset(rx_buffer, 0, sizeof(rx_buffer));
                    memset(pom_buffer, 0, sizeof(pom_buffer));
                    decrypt_size = 0;

                    //Search for clients by sockets and If client is in the list
                    //the server decrypts the data from the client
                    CLIENT *client_encrypt = search_client(p_list, i);

                    /* Reading, decrypting, verifying the received message */
                    ret_msg = salt_read_and_decrypt(&client_encrypt->channel, 
                                                    rx_buffer, 
                                                    sizeof(rx_buffer), 
                                                    &msg_in, 
                                                    pom_buffer, 
                                                    &decrypt_size, 
                                                    0);
                   /* Check if SALT_ERROR from message */
                   if(ret_msg == SALT_ERROR) 
                   {
                        printf("\tThe client disconnects from the server.\n");
                        printf("\tThe server has closed him socket\n");
                        printf("\tNumber of successfully received messages from the client %u\n", client_encrypt->count_of_messages);

                        /* Deleting the client from the server database */
                        realese_client(p_list, client_encrypt);
                        /* Deleting socket from fd_structure*/
                        FD_CLR(i, &master);
                        /* Closing socket */
                        CLOSESOCKET(i);

                        printf("\tThe client has been deleted from the client database\n\n");
                        /* List of currently connected clients */
                        listing_clients(p_list);

                        /* !!!!!!!!!!!! This continue is very important  !!!!!!!!!!!!!!!
                         *
                         * After deleting a client, server must services current clients 
                         * and listen new connections from the new client
                         */
                        continue;
                    }

                    /* Increase the number of messages from the client */
                    client_encrypt->count_of_messages++;

                    /* Shutting down the server */
                    shut_down = memcmp(pom_buffer, "123FINISH", strlen("123FINISH"));

                    /* I inform connected clients that the server is terminating its service */
                    if (shut_down == 0)
                    {   
                        printf("LAST INFO: I'm terminating my service\n");
                        memset(pom_buffer, 0, decrypt_size);

                        decrypt_size = strlen("The server shuts down it's service\n");
                        memcpy(pom_buffer,"The server shuts down it's service\n", decrypt_size);
                    }
                }
               /* Chat room service */
               SOCKET j;
               /* Search active sockets */
                for(j = 1; j <= max_socket; ++j)
                {
                    if(FD_ISSET(j, &master))
                    {
                        if (j == socket_listen || j == i)
                        {   
                            /* Also important continue */
                            continue;

                        } else 
                        {   
                            /* Cleaning the necessary buffer for encryption of data */
                            memset(tx_buffer, 0, sizeof(rx_buffer));

                            /* Search for clients by sockets and the is in the list */
                            CLIENT *client_encrypt = search_client(p_list, j);

                            /* Prepare data before send */
                            ret_msg = salt_write_begin(tx_buffer, sizeof(tx_buffer), &msg_out);
                            assert(ret_msg == SALT_SUCCESS);

                            /* 
                             * Copy clear text message to be encrypted to next encrypted package 
                             * Checking the correct parameter settings, selecting the packet type, verification
                             */
                            ret_msg = salt_write_next(&msg_out, pom_buffer, decrypt_size);
                            assert(ret_msg == SALT_SUCCESS);

                            /* Wrapping, creating encrpted messages */
                            ret_msg = salt_write_execute(&client_encrypt->channel, &msg_out, false);
                            assert(ret_msg == SALT_SUCCESS);
                            printf("\n******| Encrypting data and sending it with Salt channel |********\n");
                        }
                    } //End -> if(FD_ISSET(j, &master)
                } //End -> for(j = 1; j <= max_socket; ++j)
            } //End -> if FD_ISSET
        } //End -> for i to max_socket
        if (shut_down == 0) break;
    } //End -> while(1){....}

    /* Freeing memory of p_list (database of clients) */
    realese_list(p_list);

    return 1;
}

/* ======================== Functions for creating a database and working with it  =========================== */
   
//Function that allocates memory for the list structure and sets the head and tail to NULL
LIST *create_list()
{
    LIST *p_list = (LIST *) malloc(sizeof(LIST));
    if (p_list == NULL)
    {
        printf("Error - Out of memory.\n");
        exit(1);
    }
    p_list->p_head = NULL;
    p_list->p_tail = NULL;
    p_list->count = 0;

    return p_list;
}

//Function for realese LIST 
void realese_list(LIST *p_list)
{
    CLIENT *p_actuall = p_list->p_head;
    CLIENT *p_old;

    while (p_actuall != NULL)
    {
        p_old = p_actuall;
        p_actuall = p_actuall->p_next; 
        free(p_old);
    }
    p_list->count--;
    free(p_list);
}

//Function for create client
CLIENT *create_client()
{
    CLIENT *p_client;

    p_client = (CLIENT *) malloc(sizeof(CLIENT));
    if (p_client == NULL)
    {
        printf("Error - Out of memory.\n");
        exit(1);
    }

    return p_client;
}


//Function for delete node(client)
CLIENT * deleteNode(CLIENT * head, SOCKET sock_fd) 
{
  if(head == NULL) return NULL;

  if(head->sock_fd == sock_fd )
  {
    CLIENT *pre = head; 
    head = head->p_next;
    head->p_previous = NULL;

    free(pre);

    return head;
  }

  head->p_next=deleteNode(head->p_next,sock_fd);

  return head;
}

//Function for release client from LIST
void realese_client(LIST *p_list,CLIENT *p_client)
{
   //Check the validity of function arguments first for safety purposes
   if(p_list == NULL  || p_client == NULL) return;

   SOCKET sock_fd = p_client->sock_fd;
   CLIENT *p_head = p_list->p_head;
   CLIENT *p_tail = p_list->p_tail;

    //if list of the client is empty quite
    if(p_tail == NULL) return;


    //Test if the wanted node is the head or the tail
    if(p_head == p_tail)
    {
      if(p_head->sock_fd == sock_fd)
        {
            p_list->p_head = NULL;
            p_list->p_tail = NULL;

            free(p_head);
        }

        return;
    }

    if(p_tail->sock_fd == sock_fd)
    {
        p_list->p_tail = p_tail->p_previous;
        p_list->p_tail->p_next = NULL;

        free(p_tail);

        return;
    }   

    if(p_head->sock_fd == sock_fd)
    {
        p_list->p_head = p_head->p_next;
        p_list->p_head->p_previous = NULL;
        
        free(p_head);
        
        return;
   }
  
deleteNode(p_list->p_head,p_client->sock_fd);
}

//Function for connecting a new node to the list
void insert(LIST *p_list, 
            CLIENT *p_client)
{
      //There are some p_client on the p_list
    if (p_list->p_tail != NULL)
    {   
        //Connecting the last person as a new person
        p_list->p_tail->p_next = p_client; 
        //Joining a new person to a former last person
        p_client->p_previous = p_list->p_tail; 
        //Save a new p_tail
        p_list->p_tail = p_client; 
    }
    else 
    {   //p_list is empty

        //There is none in front of the p_client
        p_client->p_previous = NULL; 
        //Assigning a p_client to the list (head and tail)
        p_list->p_head = p_client; 
        p_list->p_tail = p_client; 
    }

    p_client->p_next = NULL;
    p_list->count++;
}


//Function for listing of clients to the console
void listing_clients(LIST *p_list)
{
    printf("Currently connected clients:\n");
    
    CLIENT *p_actuall = p_list->p_head;
    while (p_actuall != NULL)
    {
        // List of persons
        printf("(IPv4): CLIENT %s\n", p_actuall->address_buffer);
        p_actuall = p_actuall->p_next; 
    }

    printf("\n");
}

//Function for client search in the LIST and return 
CLIENT  *search_client(LIST *p_list,
                       SOCKET y)
          
{
    CLIENT *p_find = p_list->p_head;
    CLIENT *p_return_client = NULL;

    while (p_find != NULL)
    {
        if (y == (p_find->sock_fd))
        {
            p_return_client = p_find;
        }

        p_find = p_find->p_next; 
    }

    return p_return_client;
}

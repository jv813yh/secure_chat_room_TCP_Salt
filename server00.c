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


//Client structure and new data type CLIENT 
typedef struct client {
    char address_buffer[100];
    SOCKET sock_fd;
    salt_channel_t channel;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    struct client *p_next;
} CLIENT; //UZEL

//LIST structure and new data type LIST
typedef struct {
    int count;
    CLIENT *p_head;
    CLIENT *p_tail;
} LIST; //SEZNAM

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
    // 
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


//Function for connecting a new node to the list
void  insert(LIST *p_list, 
             CLIENT *p_client)
{
    // There are some people on the list
   p_client->p_next = NULL;

    // Seznam není prázdný
    if(p_list->p_tail != NULL)
    {        
        // Připojí nový uzel za poslední
        p_list->p_tail->p_next = p_client;
        // Nastaví nový ocas
        p_list->p_tail = p_client;
    }
    else // Seznam je prázdný, jen do něj vložíme uzel
    {
        p_list->p_head = p_client;
        p_list->p_tail = p_client;
    }
    p_list->count++;

}

//Function for reads encrypted message
salt_ret_t salt_read_begin_pom(salt_channel_t *p_channel, 
                               uint8_t *p_buffer, 
                               uint32_t buffer_size, 
                               salt_msg_t *p_msg, 
                               uint8_t *p_pom, 
                               uint32_t *p_size);
//Function for client search in the LIST and return 
CLIENT  *search_client(LIST *p_list,
                       SOCKET y)
          
{

    CLIENT *p_find = p_list->p_head;

    while (p_find != NULL)
    {
        if (y == (p_find->sock_fd))
        {
            return p_find;
        }

        p_find = p_find->p_next; 
    }


}


//Function for listing of people to the console
void listing_clients(LIST *p_list)
{
    printf("\nConnected clients (IPv4):\n");
    
    CLIENT *p_actuall = p_list->p_head;
    while (p_actuall != NULL)
    {
        // List of persons
        printf("%s\n", p_actuall->address_buffer);
        p_actuall = p_actuall->p_next; 
    }
}


//Function for create Salt handshake between server-klient
void salt_hndshk(CLIENT *p_client);

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

int main() { 

#if defined(_WIN32)

    //Variables
    SOCKET socket_listen;

    uint8_t rx_buffer[UINT16_MAX * 4];
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t pom_buffer[SALT_HNDSHK_BUFFER_SIZE];
    salt_msg_t msg_in;
    salt_protocols_t protocols;
    salt_msg_t msg_out;
    salt_ret_t ret_msg;
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
    getaddrinfo("192.168.100.8", "8080", &hints, &bind_address); //port 8080, generate an address suitable for the bind () function

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
    puts("Bind done");
    freeaddrinfo(bind_address); 

    printf("Listening...\n");
    if (listen(socket_listen, 5) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    //Define fd_set structure master that stores all of the active sockets 
    fd_set master;
    FD_ZERO(&master);
    FD_SET(socket_listen, &master);
    SOCKET max_socket = socket_listen;


    printf("Waiting for connections...\n");

    CLIENT *client_info;

    //Create an empty list(p_list)
    LIST *p_list = create_list();

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
                    //
                 	client_info = create_client();
                    client_info->client_len = sizeof(client_info->client_address);
                    client_info->sock_fd = accept(socket_listen,
                            (struct sockaddr*) &client_info->client_address,
                            &client_info->client_len);

                    if (!ISVALIDSOCKET(client_info->sock_fd)) {
                        fprintf(stderr, "accept() failed. (%d)\n",
                                GETSOCKETERRNO());
                        return 1;
                    }

                    FD_SET(client_info->sock_fd, &master);
                    if (client_info->sock_fd > max_socket)
                        max_socket = client_info->sock_fd;
                
                    //Prints the client address using the getnameinfo() function
                    getnameinfo((struct sockaddr*)&client_info->client_address,
                            &client_info->client_len,
                            client_info->address_buffer, 
                            sizeof(client_info->address_buffer), 0, 0,
                            NI_NUMERICHOST);
                    printf("New connection %s\n", client_info->address_buffer);
                    

                    printf("\nWaiting for succeses Salt handshake...\n");

                    //Salt handshake 
                    salt_hndshk(client_info);

                    //Insert client to the list of clients
                    insert(p_list, client_info);

                    //List of clients connected to the server with a successful Salt handshake       
                    listing_clients(p_list);       
                } else {
                    
                    memset(rx_buffer, 0, sizeof(hndsk_buffer));

                    //Search for clients by sockets and the is in the list
                    //the server decrypts the data from the client

                    CLIENT *client_encrypt = create_client();

                    client_encrypt = search_client(p_list, i);

                    salt_read_begin_pom(&client_encrypt->channel, rx_buffer, 
                                       sizeof(rx_buffer), &msg_in, pom_buffer, &decrypt_size);
                    free(client_encrypt);

                    continue;
                }
            } //if FD_ISSET
        } //for i to max_socket
    } //while(1)
    
    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

    WSACleanup();
#endif

    //Freeing memory of p_list
    realese_list(p_list);
    printf("Finished.\n");
    return 0;
}


void salt_hndshk(CLIENT *p_client)
{

    //CLIENT *p_client = (context *);
    //SOCKET sock = p_client->sock_fd;

    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t rx_buffer[UINT16_MAX * 4];
    uint8_t pom_buffer[SALT_HNDSHK_BUFFER_SIZE];
    uint8_t tx_buffer[UINT16_MAX * 4];
    uint8_t protocol_buffer[128];
    uint32_t verify = 0, decrypt_size;

    salt_msg_t msg_out;
    salt_ret_t ret;
    salt_ret_t ret_msg;
    salt_msg_t msg_in;
    salt_protocols_t protocols;

    clock_t start_t, end_t;

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
    salt_set_delay_threshold(&p_client->channel, 20000);

    start_t = clock();
    //Salt handshake 
    ret = salt_handshake(&p_client->channel, NULL);
    end_t = clock();

    printf("\n");
    printf("\t\n***** SERVER:Salt channelv2 handshake lasted: %6.6f sec. *****\n", ((double) (end_t -
            start_t) / (CLOCKS_PER_SEC))); 
    printf("\n");

    //Testing success for Salt handshake
    while (ret != SALT_SUCCESS) {

        if (ret == SALT_ERROR) {
            printf("Error during handshake:\r\n");
            printf("Salt error: 0x%02x\r\n", p_client->channel.err_code);
            printf("Salt error read: 0x%02x\r\n", p_client->channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", p_client->channel.write_channel.err_code);
            printf("Connection closed.\r\n");
            CLOSESOCKET(p_client->sock_fd);
            free(p_client);
            break;
        }

        ret = salt_handshake(&p_client->channel, NULL);
    }

    if (ret == SALT_SUCCESS) {
    printf("\nSalt handshake successful\r\n");
    printf("\n");
    verify = 1;
    }
      
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



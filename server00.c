/**
 * ===============================================
 * server00.c   v.1.8
 * 
 * KEMT FEI TUKE, Diploma thesis
 *
 * Secure chat room. 
 * Clients connect to the server 
 * (with IP address and port number) within the TCP connection. 
 * communication client-server is cryptographically secured
 * by the Salt-channel protocol. The server forwards secure
 * data to all connected clients.
 *
 * Encryption:
 *      - Key exchange: X25519
 *      - Encryption: XSalsa20 stream cipher
 *      - Authentication: Poly1305 MAC
 *
 *  Signatures:
 *      - Ed25519
 *
 *  Hashing:
 *      - SHA512
 *
 * Deployment of Salt-Channelv2 cryptographic 
 * protocol on TCP communication channel.
 *
 * Compileable on Windows with WinLibs standalone build 
 * of GCC and MinGW-w64.
 *
 * Compileable on Linux with 
 *
 * For more details on salt channel see:
 * https://github.com/assaabloy-ppi/salt-channel-c
 *
 * Author-Jozef Vendel  Create date- 09.5.2021 
 * ===============================================
 */

/* ======== Includes ===================================== */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Libraries needed for networking work on Windows/Linux */
#include "win_linux_sockets.h"

/* ===== Salt-channel libraries ===== */
#include "salt.h"
#include "salt_io.h"
#include "salti_util.h"

/*
 * Functions required to deploy the Salt channelv2 protocol on
 * the TCP communication channel 
 */
#include "tcp_salt_chat_room.h"


int main(int argc, char *argv[]) 
{   
    //Input from the command line
    if (argc < 3) 
    {
        fprintf(stderr, "usage: server IPV4  port\n");
        return 1;
    } 

#if defined(_WIN32)
    //The MAKEWORD macro allows us to request Winsock version 2.2, ONLY FOR WINDOWS !!!
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) { //inicializacia Winscok-u
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
#endif

/* ==== Creating socket and TCP connection ==== */
    
    /* 
     * Creates a socket (return this socket) with which it waits 
     * for a connection from the client   
     */
    SOCKET socket_listen = create_socket_and_listen(argv[1], argv[2]);
    printf("Waiting for connections...\n");

/* ==== The whole implementation of secure chat communication by Salt channel protocol ==== */

    uint32_t check_room_service = salt_chat_room_service(socket_listen);
    if (check_room_service != 1)
    {
        printf("Error performing chat service\n");
        return 1;
    }

/* ========  End of application  ========================= */
    
    printf("\nClosing connection...\n");
    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

    /* Cleanning Winsock, ONLY FOR WINDOWS !!! */
#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}





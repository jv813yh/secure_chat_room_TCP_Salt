/**
 * ===============================================
 * client00.c   v.1.2
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
 * Author-Jozef Vendel  Create date- 04.5.2021 
 * ===============================================
 */

/* ======== Includes ===================================== */

/* Basic libraries for working in C. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Libraries needed for networking work on Windows/Linux */
#include "win_linux_sockets.h"

/*
 * Functions required to deploy the Salt channelv2 protocol on
 * the TCP communication channel 
 */
#include "tcp_salt_chat_room.h"

int main(int argc, char *argv[]) 
{
    /* Checking the correct program parameters */
    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        return 1;
    }

#if defined(_WIN32)
    //The MAKEWORD macro allows us to request Winsock version 2.2, ONLY FOR WINDOWS !!! 
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
#endif

/* ======= Creating client socket and TCP connection ======= */
     /* 
     * It will create a socket with which the client will 
     * connect to the server
     */
    SOCKET socket_peer = create_socket_and_connect(argv[1], argv[2]);

    /* Connection control */
    if (ISVALIDSOCKET(socket_peer)) printf("\nConnection to the server :)\n");
    else printf("\nError connecting to server :(\n");

    /*
     * TCP connection was successfully established in the 
     * client-server architecture.
     * 
     * Now, We are implementing salt channel v2 
     * and We will try a salt handshake with the server
     * and after a successful salt handshake, We can exchange data
     */
    printf("Connected.\n");
    printf("TCP was successfully performed...\n\nCreating Salt Hanshake...\n");
          
/* =====  Salt-channel  implementation, Salt Handshake, exchanging secure data   ==== */
    /*
     * Function for establishing a connection using the Salt handshake process 
     * and exchanging secure data by protocol
     */
    connection_and_writting(&socket_peer);

/* ========  End of application  ========================= */

    printf("\nClosing connection...\n");
    printf("Closing socket...\n");
    CLOSESOCKET(socket_peer);

    /* Cleanning Winsock, ONLY FOR WINDOWS !!! */
#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}



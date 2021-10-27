/*
 * salt_io.c    v.0.0
 *
 *    Input, Output, Timestamp
 *
 * Functions needed for sending messages, receiving messages, creating time stamps in the Salt channel protocol
 *
 * Author-Jozef Vendel  Date- 1.5.2021 
 * ===============================================
 */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

//Library of Salt channelv2
#include "salti_util.h"
#include "salt_io.h"

////Libraries for working with network tools in Windows
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

//Getting time
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

//Function for sending messages
salt_ret_t my_write(salt_io_channel_t *p_wchannel){

#if defined(_WIN32)

    uint32_t bytes_sent;

    //The MAKEWORD macro allows us to request Winsock version 2.2
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }

    //Decriptor of socket
    SOCKET sock = *((SOCKET *) p_wchannel->p_context);

    if (sock <= 0) {
        return SALT_ERROR;
    }
    
    //Sending messages through socket
    bytes_sent = send(sock, p_wchannel->p_data, p_wchannel->size_expected, 0);
    printf("Sent %d bytes.\n", bytes_sent);
    
    //Verification
    if (bytes_sent < 1) {
        printf("Less than 1 bytes was sent.\nSocket was closed\n");
        CLOSESOCKET(sock);
    }
    
    //Addition size of bytes
    p_wchannel->size += bytes_sent;

    //Closing Winsock
    WSACleanup();
    return SALT_SUCCESS;

#endif   
}

////Function for receiving messages
salt_ret_t my_read(salt_io_channel_t *p_rchannel){

#if defined(_WIN32)

    uint32_t bytes_received;
    
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }

    //Decriptor of socket
    SOCKET sock = *((SOCKET *) p_rchannel->p_context);

    if (sock <= 0) {
        return SALT_ERROR;
    }

    //Receiving messages through socket
    bytes_received = recv(sock, p_rchannel->p_data, p_rchannel->size_expected, 0);
    
    //Verification
    if (bytes_received < 1) {
        printf("Less than 1 bytes was received.\nSocket was closed\n");
        CLOSESOCKET(sock);
    }
    printf("Received %d bytes\n", bytes_received);
    
    
    //Addition size of bytes
    p_rchannel->size += bytes_received;

    //Closing Winsock
    WSACleanup();
    //return(p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
    return SALT_SUCCESS;
    
#endif
}

//A function to create a timestamp that is included in sent/receivd messages
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time){
    
    (void) *p_time;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t curr_time = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    uint32_t rel_time = curr_time % 0xFFFFFFFF;
    *time = rel_time;
    return SALT_SUCCESS;
}


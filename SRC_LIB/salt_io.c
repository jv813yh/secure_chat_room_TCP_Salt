/*
 * salt_io.c    v.0.8
 *
 * Input, Output, Timestamp
 *
 * Functions needed for sending/receiving messages, creating 
 * time stamps in the Salt channelv2 protocol on TCP/IP
 *
 * Windows/Linux  
 *
 * Author-Jozef Vendel  Create date- 28.12.2021 
 *
 * KEMT FEI TUKE, Diploma thesis
 * ===============================================
 */

/*======= Includes ========================================*/

/* ==== Basic libraries for working in C ================= */
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

/* ======= Salt-channel libraries ======================== */
#include "salti_util.h"
#include "salt_io.h"

/* ==== Libraries for Windows/Linux sockets programming == */
#include "win_linux_sockets.h"

/*======= Local function prototypes =======================*/

/*======= Global function implementations =================*/

/**
 * The salt-channel-c implements a delay attack protection. 
 * This means that both peers sends a time relative to the 
 * first messages sent. This means that from the timestamp 
 * in a package an expected time could be derived. 
 *
 * If this one differs more than the threshold a delay attack
 * might be present and the salt-channel implementation 
 * will return error. 
 *
 * For this feature to work the used must
 * inject a get time implementation.
 *
 */
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time);

salt_time_t my_time = {
    get_time,
    NULL
};

/**
 * Function for sending messages via the socket.
 *
 * Return the size of bytes sent and decides 
 * accordingly whether all bytes have been sent or
 * whether another bytes need to be sent
 * 
 * @return:
 * 
 * SALT_SUCCESS -> all bytes have been sent
 * SALT_PENDING -> another bytes need to be sent
 *
 */

salt_ret_t my_write(salt_io_channel_t *p_wchannel)
{
    /* Decriptor of socket  */
#if defined(_WIN32)
/* ======= WINDOWS =================================== */
    /* Decriptor of socket  */
    SOCKET sock = *((SOCKET *) p_wchannel->p_context);
#else 
/* ======= LINUX =================================== */
    int sock = *((int *) p_wchannel->p_context);
#endif

    /* Checking that the socket number is assigned correctly */
    if (sock <= 0) 
    {
        printf("The socket number is assigned incorrectly\n");
        return SALT_ERROR;
    }

    uint32_t bytes_sent;
    
    /* The size of bytes what We need to send  */
    uint32_t to_write = p_wchannel->size_expected - p_wchannel->size;

    /**
     * Sending data via the sock. 
     * 
     * @param p_wchannel->p_data[p_wchannel->size]: is
     * a pointer to a buffer 
     * 
     * @param to_write: is the size 
     * of the buffer in bytes.
     * 
     * @return -1 in case of an error, otherwise it returns the amount of bytes sent.
     * 
     */ 

    bytes_sent = send(sock,
                      (char *) &p_wchannel->p_data[p_wchannel->size], 
                      to_write,
                      0);

    printf("\n******| Salt-channelv2 I/O |******\n");

    /* Verification */
    if (bytes_sent == 0 || bytes_sent == -1)
    {   
        printf("\nLess than 1 bytes was sent.\nSocket was closed\n");
        p_wchannel->err_code = SALT_ERR_CONNECTION_CLOSED;

        CLOSESOCKET(sock);

        return SALT_ERROR;

    } else printf("Sent %d bytes.\n", bytes_sent);

    /*  */
    SALT_HEXDUMP_DEBUG(&p_wchannel->p_data[p_wchannel->size], bytes_sent);
    
    /* Addition size of bytes */
    p_wchannel->size += bytes_sent;

    return (p_wchannel->size == p_wchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
}

/**
 * Function for receiving messages via the socket.
 *
 * Return the size of bytes received and decides 
 * accordingly whether all bytes have been received or
 * whether another bytes need to be received
 * 
 * @return:
 * 
 * SALT_SUCCESS -> all bytes have been received
 * SALT_PENDING -> another bytes need to be received
 *
 */
salt_ret_t my_read(salt_io_channel_t *p_rchannel)
{
    /* Decriptor of socket  */
#if defined(_WIN32)
/* ======= WINDOWS =================================== */
    /* Decriptor of socket  */
    SOCKET sock = *((SOCKET *) p_rchannel->p_context);
#else 
/* ======= LINUX =================================== */
    int sock = *((int *) p_rchannel->p_context);
#endif

    /* Checking that the socket number is assigned correctly */
    if (sock <= 0) {
        return SALT_ERROR;
    }

    uint32_t bytes_received;

    /* The size of bytes what We need to receive  */
    uint32_t to_read = p_rchannel->size_expected - p_rchannel->size;

    /**
     * Receiving data via the sock. 
     * 
     * @param p_rchannel->p_data[p_rchannel->size]: is
     * a pointer to a buffer 
     * 
     * @param to_read: is the size 
     * of the buffer in bytes.
     * 
     * @return -1 in case of an error, 
     * otherwise it returns the size of bytes received
     * 
     */ 
    bytes_received = recv(sock,
                          (char *)  &p_rchannel->p_data[p_rchannel->size],
                          to_read,
                          0);

    printf("\n******| Salt-channelv2 I/O |******\n");

    /* Verification */
    if (bytes_received == 0 || bytes_received == -1) 
    {
        printf("\nLess than 1 bytes was received.\nSocket was closed\n");
        p_rchannel->err_code = SALT_ERR_CONNECTION_CLOSED;

        CLOSESOCKET(sock);

        return SALT_ERROR;

    } else printf("Received %d bytes\n", bytes_received);
    
    /*    */
    SALT_HEXDUMP_DEBUG(&p_rchannel->p_data[p_rchannel->size], bytes_received);
    /* Addition size of bytes */
    p_rchannel->size += bytes_received;

    return(p_rchannel->size == p_rchannel->size_expected) ? SALT_SUCCESS : SALT_PENDING;
}

//A function to create a timestamp that is included in sent/receivd messages
static salt_ret_t get_time(salt_time_t *p_time, uint32_t *time)
{
    
    (void) *p_time;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    uint64_t curr_time = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    uint32_t rel_time = curr_time % 0xFFFFFFFF;
    
    *time = rel_time;

    return SALT_SUCCESS;
    return SALT_SUCCESS;
}
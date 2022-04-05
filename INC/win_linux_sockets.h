/*
 * @file win_linux_sockets.h
 * 
 * Libraries needed for networking work  on Windows / Linux 
 *
 * Author-Jozef Vendel  Create date- 10.12.2021 
 *
 * KEMT FEI TUKE, Diploma thesis
 */

// Libraries for working with network tools on Windows
#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

// pragma comment not needed because I use the Makefile file -> flag -lws2_32
// #pragma comment(lib, "ws2_32.lib")

#else
// Libraries for working with network tools on Linux
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif

/*
 * With the modified functions, it is possible to use the same functions 
 * on both operating systems
 */
#if defined(_WIN32)
// Constants for working with sockets on Windows
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

#else
// Constants for working with sockets on Linux
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)
#endif

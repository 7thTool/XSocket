/*
 * Copyright: 7thTool Open Source (i7thTool@qq.com)
 *
 * Version	: 1.1.1
 * Author	: Scott
 * Project	: http://git.oschina.net/7thTool/XSocket
 * Blog		: http://blog.csdn.net/zhangzq86
 *
 * LICENSED UNDER THE GNU LESSER GENERAL PUBLIC LICENSE, VERSION 2.1 (THE "LICENSE");
 * YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
 * UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
 * DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 * SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
 * LIMITATIONS UNDER THE LICENSE.
 */

#ifndef _H_XSOCKETDEF_H_
#define _H_XSOCKETDEF_H_

#ifdef XSOCKET_DLL
#ifdef XSOCKET_EXPORTS
#define XSOCKET_API __declspec(dllexport)
#else
#define XSOCKET_API __declspec(dllimport)
#endif//XSOCKET_EXPORTS
#else
#define	XSOCKET_API 
#ifdef XSOCKET_EXPORTS
#else
#endif//
#endif//XSOCKET_DLL

#ifdef WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN		// 从 Windows 头中排除极少使用的资料
#endif//WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <tchar.h>
#include <memory.h>
#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif//MSG_NOSIGNAL

#else //LINUX

#include <sys/types.h> 
#include <sys/syscall.h>
#include <sys/timeb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>

#ifndef stricmp
#define stricmp strcasecmp 
#endif//stricmp

#ifndef wcsicmp
#define wcsicmp wcscasecmp 
#endif//wcsicmp

#ifndef strnicmp
#define strnicmp strncasecmp 
#endif//strnicmp

#ifndef wcsnicmp
#define wcsnicmp wcsncasecmp 
#endif//wcsnicmp

#ifndef SOCKET
typedef int SOCKET;
#endif//SOCKET

#ifndef FAR
#define FAR
#endif//

typedef struct sockaddr SOCKADDR;
typedef struct sockaddr *PSOCKADDR;
typedef struct sockaddr FAR *LPSOCKADDR;

typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr_storage *PSOCKADDR_STORAGE;
typedef struct sockaddr_storage FAR *LPSOCKADDR_STORAGE;

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in *PSOCKADDR_IN;
typedef struct sockaddr_in FAR *LPSOCKADDR_IN;

typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef struct sockaddr_in6 *PSOCKADDR_IN6;
typedef struct sockaddr_in6 FAR *LPSOCKADDR_IN6;

typedef struct linger LINGER;
typedef struct linger *PLINGER;
typedef struct linger FAR *LPLINGER;

typedef struct in_addr IN_ADDR;
typedef struct in_addr *PIN_ADDR;
typedef struct in_addr FAR *LPIN_ADDR;

typedef fd_set FD_SET;
typedef fd_set *PFD_SET;
typedef fd_set FAR *LPFD_SET;

typedef struct hostent HOSTENT;
typedef struct hostent *PHOSTENT;
typedef struct hostent FAR *LPHOSTENT;

typedef struct servent SERVENT;
typedef struct servent *PSERVENT;
typedef struct servent FAR *LPSERVENT;

typedef struct protoent PROTOENT;
typedef struct protoent *PPROTOENT;
typedef struct protoent FAR *LPPROTOENT;

typedef struct timeval TIMEVAL;
typedef struct timeval *PTIMEVAL;
typedef struct timeval FAR *LPTIMEVAL;

#ifndef SOCKET_ERROR
#define SOCKET_ERROR  (-1)  
#endif//SOCKET_ERROR

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (SOCKET)(~0)  
#endif//INVALID_SOCKET

/*
 * Define flags to be used with the select.
 */
#ifndef FD_READ
#define FD_READ         0x01
#define FD_WRITE        0x02
#define FD_OOB          0x04
#define FD_ACCEPT       0x08
#define FD_CONNECT      0x10
#define FD_CLOSE        0x20
#endif//

#endif//

#define FD_IDLE			0x80

#ifndef byte
typedef unsigned char byte;
#endif//

#ifndef isnumber
#define isnumber(n) (n >= '0' && n <= '9')
#endif

#ifndef ishex
#define ishex(n) ((n >= '0' && n <= '9') || (n >= 'a' && n<='f') || (n >= 'A' && n <= 'F'))
#endif

#define isallowed(n) ((n >= '0' && n <= '9') || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '*' && n <= '/') || n == '_')

//#ifndef vsprintf
//#define vsprintf vsnprintf
//#endif//vsprintf

#define SAFAMILY(sa) (&(((struct SOCKADDR_IN *)sa)->sin_family))

#ifndef NOIPV6
#define SAPORT(sa)  (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? &((struct SOCKADDR_IN6 *)sa)->sin6_port : &((struct SOCKADDR_IN *)sa)->sin_port)
#define SAADDR(sa)  (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? (unsigned char *)&((struct SOCKADDR_IN6 *)sa)->sin6_addr : (unsigned char *)&((struct SOCKADDR_IN *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? 16:4)
#define SASOCK(sa) (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? PF_INET6:PF_INET)
#define SASIZE(sa) (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? sizeof(struct SOCKADDR_IN6):sizeof(struct SOCKADDR_IN))
#define SAISNULL(sa) (!memcmp(((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? (unsigned char *)&((struct SOCKADDR_IN6 *)sa)->sin6_addr : (unsigned char *)&((struct SOCKADDR_IN *)sa)->sin_addr.s_addr, NULLADDR,  (((struct SOCKADDR_IN *)sa)->sin_family == AF_INET6? 16:4))) 
#else
#define SAPORT(sa)  (&((struct SOCKADDR_IN *)sa)->sin_port)
#define SAADDR(sa)  ((unsigned char *)&((struct SOCKADDR_IN *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (4)
#define SASOCK(sa) (PF_INET)
#define SASIZE(sa) (sizeof(struct SOCKADDR_IN))
#define SAISNULL(sa) (((struct SOCKADDR_IN *)sa)->sin_addr.s_addr == 0) 
#endif

#ifndef ASSERT
#include <assert.h>
#define ASSERT assert
#endif//

#ifndef ENSURE
#include <assert.h>
#define ENSURE assert
#endif//

#ifndef PRINTF
#if 1
#define PRINTF(format,...) printf(format, ##__VA_ARGS__)
#else
#define PRINTF(format,...) 
#endif//
#endif//
//#ifdef __DEBUG__  
//#define DEBUG(format,...) printf("File: "__FILE__", Line: %05d: "format"\n", __LINE__, ##__VA_ARGS__)  
//#else  
//#define DEBUG(format,...) 
//#endif  

#endif//_H_XSOCKETDEF_H_
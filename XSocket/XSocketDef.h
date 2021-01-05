/*
 * Copyright: 7thTool Open Source <i7thTool@qq.com>
 * All rights reserved.
 * 
 * Author	: Scott
 * Email	：i7thTool@qq.com
 * Blog		: http://blog.csdn.net/zhangzq86
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

typedef intptr_t ssize_t;

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

#if __cpp_inline_variables >= 201606L
#define INLINE_GLOBAL inline // C++17
#elif defined(_MSC_VER)
#define INLINE_GLOBAL __declspec(selectany) // Visual C++
#else
#define INLINE_GLOBAL __attribute__((weak)) // GCC/Clang
#endif

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

// #ifdef WIN32
// #define I64D "%I64d"
// #else
// #define I64D "%lld"
// #endif
// #ifdef WIN32
// #define I64U "%I64u"
// #else
// #define I64U "%llu"
// #endif

//DATE TIME [日志级别] [标识] 内容

#ifndef XSOCKET_LOGOUT
#define XSOCKET_LOGOUT(format,...) printf(format "\n", ##__VA_ARGS__)
#endif//

#ifndef XSOCKET_LOG4E 
#define XSOCKET_LOG4E(format,...) XSOCKET_LOGOUT("[ERROR] [%s:%d] " format, __FILE__, __LINE__, ##__VA_ARGS__)
#endif//

#ifndef XSOCKET_LOG4W 
#define XSOCKET_LOG4W(format,...) XSOCKET_LOGOUT("[WARN] " format, ##__VA_ARGS__)
#endif//

#ifndef XSOCKET_LOG4I 
#define XSOCKET_LOG4I(format,...) XSOCKET_LOGOUT("[INFO] " format, ##__VA_ARGS__)
#endif//

#ifndef XSOCKET_LOG4D 
#define XSOCKET_LOG4D(format,...) XSOCKET_LOGOUT("[DEBUG] [%s] " format, __FUNCTION__, ##__VA_ARGS__)
#endif//

#ifndef PRINTF
#define PRINTF XSOCKET_LOG4D
#endif//

#ifndef ASSERT
#include <assert.h>
#ifdef _DEBUG
#define ASSERT(exp) do { if(!(exp)) { XSOCKET_LOG4E("ASSERT"); } assert(exp); } while(0)
#else
#define ASSERT(exp) 
#endif
#endif//

#ifndef ENSURE
#ifdef _DEBUG
#include <assert.h>
#define ENSURE(exp) do { if(!(exp)) { XSOCKET_LOG4E("ENSURE"); } assert(exp); } while(0)
#else
#define ENSURE(exp) 
#endif
#endif//

#ifndef USE_MEMORY_POOL
#define USE_MEMORY_POOL 0
#endif

#ifndef USE_ZLIB
#define USE_ZLIB 1
#endif
#ifndef USE_OPENSSL
#define USE_OPENSSL 0
#endif
#ifndef USE_WEBSOCKET
#define USE_WEBSOCKET 0
#endif

//////////////////////////////////////////////////////////////////////////
//IPV4->IPV6
//映射项 功能说明 IPv4 IPv6
//常量定义 地址族 AF_INET AF_INET6
//协议族 PF_INET PF_INET6
//IP地址结构体 结构体 sockaddr_in sockaddr_in6
//结构体成员:套接口长度 sin_len sin6_len
//结构体成员:协议族 sin_family sin6_family
//结构体成员:端口号 sin_port sin6_port
//地址 通配地址 INADDR_ANY in6addr_any
//环回地址 INADDR_LOOPBACK in6addr_loopback
//地址－表达式转换函数 字符串地址转为IP地址 inet_aton() inet_pton()
//IP地址结构转为字符串 inet_ntoa() inet_ntop( )
//名字－地址转换函数 根据名字获得IP地址 gethostbyname() getaddrinfo()
//根据IP地址获得名字 gethostbyaddr() getnameinfo()
//根据名字获得IP地址 gethostbyname2() getaddrinfo()
//根据服务名获得全部服务信息 getservbyname() getaddrinfo ()
//根据服务端口获得全部服务信息 getservbyport() getaddrinfo()
//
//IPV6地址fe80::21a:a5ff:fec1:1060%6后面跟的百分号6是接口(设备标识符)。若是想用windows链接linux端的机器，那么ping的时候，就得首先加上linux端的IPv6地址，然后再加上自己windows端的设备号。
//例如：
//linux机器ipv6地址： fe80::4e0f:6eff:fed8:489a/64
//windows机器ipv6地址：fe80::21a:a5ff:fec1:1060%6
//在windows机器ping命令： ping fe80::4e0f:6eff:fed8:489a%6 （即：目标地址%本地接口）

#ifndef USE_IPV6
#define USE_IPV6 0
#endif//
#if USE_IPV6
#define SockAddrType SOCKADDR_IN6
#define AF_INETType AF_INET6
#else
#define SockAddrType SOCKADDR_IN
#define AF_INETType AF_INET
#endif//

#ifdef WIN32
#if USE_OPENSSL
#ifndef USE_IOCP
#define USE_IOCP 0
#endif
#else
#ifndef USE_IOCP
#define USE_IOCP 1
#endif
#endif
#else
#ifndef USE_EPOLL
#define USE_EPOLL 1
#endif
#if USE_EPOLL
#ifndef USE_EPOLLET
#define USE_EPOLLET 1
#endif//
#endif//
#endif//

#define ChinaDNS1 "119.29.29.29"
#define ChinaDNS2 "223.5.5.5"
#define InternationalDNS1 "8.8.8.8"
#define InternationalDNS2 "8.8.4.4"

#define DNSPort 53
#define DNSPort2 5353
#define TLSDNSPort 853
#define HTTPSDNSPort 443

#define HTTPPort 80
#define HTTPPort2 8080
#define HTTPSPort 443

#endif//_H_XSOCKETDEF_H_
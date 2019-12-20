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

#ifndef _H_XSOCKET_H_
#define _H_XSOCKET_H_

#include "XSocketDef.h"

namespace XSocket {

	//std::chrono::duration<int,std::milli>
	//std::chrono::system_clock::now();
	//std::chrono::steady_clock::now();
	//std::chrono::high_resolution_clock::now()
	//to_time_t() time_point转换成time_t秒
	//from_time_t() 从time_t转换成time_point
	XSOCKET_API size_t Tick();

/*!
 *	@brief Socket封装.
 *
 *	封装Socket的基本操作
 */
class XSOCKET_API Socket
{
public:
	static long Init();
	static void Term();

	// double H2N(double n);
	// double N2H(double n);
	// float H2N(float n);
	// float N2H(float n);
	// uint64_t H2N(uint64_t n);
	// uint64_t N2H(uint64_t n);
	static u_long H2N(u_long n);
	static u_long N2H(u_long n);
	static u_short H2N(u_short n);
	static u_short N2H(u_short n);

	static u_long Ip2N(const char* ip);
	static const char* N2Ip(u_long ip);
	static const char* Url2Ip(const char* url);

	//in_addr,in6_addr
	static int IpStr2IpAddr(const char* ip, int af, void* p);
	static const char* IpAddr2IpStr(void* p, int af, char* ip, int ip_len);
	
	static int GetAddrInfo( const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result);
	static void SetAddrPort(struct sockaddr * addr, u_short port);
	// static void FreeAddrInfo( const struct addrinfo *ai);

	static u_short SockAddr2Port(const SOCKADDR* lpSockAddr, int nSockAddrLen);
	static const char* SockAddr2IpStr(const SOCKADDR* lpSockAddr, int nSockAddrLen, char* str, int len);
	static const char* SockAddr2Str(const SOCKADDR* lpSockAddr, int nSockAddrLen, char* str, int len);

	static const char* Url2IpStr(const char* url, char* str, int len);
	
	static SOCKET Create(int nSockAf, int nSockType, int nSockProtocol);

	static bool IsSocket(SOCKET Sock);

	enum { Receives = 0, Sends = 1, Both = 2 };
	static int ShutDown(SOCKET Sock, int nHow);
	static int Close(SOCKET Sock);
	
	static int Bind(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen);
	static int Connect(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen);
	static int Listen(SOCKET Sock, int nConnectionBacklog);
	static SOCKET Accept(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	static int Send(SOCKET Sock, const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	static int Receive(SOCKET Sock, char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	//int SyncSend(SOCKET Sock, const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	//int SyncReceive(SOCKET Sock, char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	static int SendTo(SOCKET Sock, const char* lpBuf, int nBufLen,
		const SOCKADDR* lpSockAddr = 0, int nSockAddrLen = 0, int nFlags = MSG_NOSIGNAL);
	static int ReceiveFrom(SOCKET Sock, char* lpBuf, int nBufLen, 
		SOCKADDR* lpSockAddr = 0, int* lpSockAddrLen = 0, int nFlags = MSG_NOSIGNAL);

	static int IOCtl(SOCKET Sock, long lCommand, u_long* lpArgument);
	static int IOCtl(SOCKET Sock, long lCommand, u_long Argument);
	static int GetSockOpt(SOCKET Sock, int nLevel, int nOptionName, void* lpOptionValue, int* lpOptionLen);
	static int GetSockOpt(SOCKET Sock, int nLevel, int nOptionName, void* lpOptionValue, int nOptionLen);
	static int SetSockOpt(SOCKET Sock, int nLevel, int nOptionName, const void* lpOptionValue, int nOptionLen);
	static int SetSendTimeOut(SOCKET Sock, int TimeOut);
	static int SetRecvTimeOut(SOCKET Sock, int TimeOut);
	static int GetSendTimeOut(SOCKET Sock);
	static int GetRecvTimeOut(SOCKET Sock);
	static int SetKeepAlive(SOCKET Sock, u_long onoff, u_long time = 30*1000);

	static int GetPeerName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	static int GetSockName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);

	static int GetLastError();
	static void SetLastError(int nError);

	static int GetErrorMessage(int nError, char* lpszMessage, int nMessageLen);
	static int GetErrorMessage(int nError, wchar_t* lpszMessage, int nMessageLen);
protected:
	SOCKET sock_;
public:
	Socket(SOCKET Sock = INVALID_SOCKET):sock_(Sock) { }
	~Socket() { }

	inline operator SOCKET() const { return sock_; }

	inline bool IsSocket() { 
#if 0
		if(IsSocket(sock_)) {
			int OptVal = 0;
			if(GetSockOpt(SO_TYPE, (void*)&OptVal, sizeof OptVal) == SOCKET_ERROR) {
				if(GetLastError() == WSAENOTSOCK) {
					sock_ = INVALID_SOCKET;
					return false;
				}
			}
			return true;
		}
		return false;
#else
		return IsSocket(sock_);
#endif//
	}

	inline SOCKET Open(int nSockAf = AF_INET, int nSockType = SOCK_STREAM, int nSockProtocol = 0) { return Attach(Create(nSockAf, nSockType, nSockProtocol)); }
	inline SOCKET Attach(SOCKET Sock) { SOCKET oSock = sock_; sock_ = Sock; return oSock; }
	inline SOCKET Detach() { return Attach(INVALID_SOCKET); }
	inline int ShutDown(int nHow = Both) { return ShutDown(sock_, nHow); }
	inline int Close() { if (IsSocket()) { return Close(Detach()); } return 0; }

	inline int Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen) { return Bind(sock_, lpSockAddr, nSockAddrLen); }
	inline int Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen) { return Connect(sock_, lpSockAddr, nSockAddrLen); }
	inline int Listen(int nConnectionBacklog = 5) { return Listen(sock_, nConnectionBacklog); }
	inline SOCKET Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return Accept(sock_, lpSockAddr, lpSockAddrLen); }
	inline int Send(const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return Send(sock_, lpBuf, nBufLen, nFlags); }
	inline int Receive(char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return Receive(sock_, lpBuf, nBufLen, nFlags); }
	//inline int SyncSend(const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return SyncSend(sock_, lpBuf, nBufLen, nFlags); }
	//inline int SyncReceive(char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return SyncReceive(sock_, lpBuf, nBufLen, nFlags); }
	inline int SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags = MSG_NOSIGNAL) 
	{ return SendTo(sock_, lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags); }
	inline int ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags = MSG_NOSIGNAL)
	{ return ReceiveFrom(sock_, lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags); }

	inline int GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return GetPeerName(sock_, lpSockAddr, lpSockAddrLen); }
	inline int GetSockName(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return GetSockName(sock_, lpSockAddr, lpSockAddrLen); }

	inline int IOCtl(long lCommand, u_long* lpArgument) { return IOCtl(sock_, lCommand, lpArgument); }
	inline int IOCtl(long lCommand, u_long Argument)  { return IOCtl(sock_, lCommand, Argument); }
	inline int GetSockOpt(int nLevel, int nOptionName, void* lpOptionValue, int nOptionLen) 
	{ return GetSockOpt(sock_, nLevel, nOptionName, lpOptionValue, &nOptionLen); }
	inline int SetSockOpt(int nLevel, int nOptionName, const void* lpOptionValue, int nOptionLen)
	{	return SetSockOpt(sock_, nLevel, nOptionName, lpOptionValue, nOptionLen); }
	inline int SetSockOpt(int nLevel, int nOptionName, u_long OptionValue)
	{ return SetSockOpt(sock_, nLevel, nOptionName, &OptionValue, sizeof(OptionValue)); }
	inline int SetSendTimeOut(int TimeOut) { return SetSendTimeOut(sock_, TimeOut); }
	inline int SetRecvTimeOut(int TimeOut) { return SetRecvTimeOut(sock_, TimeOut); }
	inline int GetSendTimeOut() { return GetSendTimeOut(sock_); }
	inline int GetRecvTimeOut() { return GetRecvTimeOut(sock_); }
	inline int SetKeepAlive(u_long onoff, u_long time = 30*1000) { return SetKeepAlive(sock_, onoff, time); }
};

}

#endif//_H_XSOCKET_H_
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
	size_t Tick();

	long InitNetEnv();
	void ReleaseNetEnv();

	double H2N(double n);
	double N2H(double n);
	float H2N(float n);
	float N2H(float n);
	uint64_t H2N(uint64_t n);
	uint64_t N2H(uint64_t n);
	u_long H2N(u_long n);
	u_long N2H(u_long n);
	u_short H2N(u_short n);
	u_short N2H(u_short n);

	unsigned long Ip2N(const char* Ip);
	const char* N2Ip(unsigned long Ip);
	const char* Url2Ip(const char* Url);
	int GetAddrInfo( const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result);
	void SetAddrInfo(struct sockaddr * addr, u_short port);

	SOCKET Open(int nSockAf, int nSockType, int nSockProtocol);

	bool IsSocket(SOCKET Sock);

	enum { Receives = 0, Sends = 1, Both = 2 };
	int ShutDown(SOCKET Sock, int nHow);
	int Close(SOCKET Sock);
	
	SOCKET Accept(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	int Bind(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen);
	int Connect(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen);
	int Listen(SOCKET Sock, int nConnectionBacklog);
	int Send(SOCKET Sock, const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	int Receive(SOCKET Sock, char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	//int SyncSend(SOCKET Sock, const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	//int SyncReceive(SOCKET Sock, char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL);
	int SendTo(SOCKET Sock, const char* lpBuf, int nBufLen,
		const SOCKADDR* lpSockAddr = 0, int nSockAddrLen = 0, int nFlags = MSG_NOSIGNAL);
	int ReceiveFrom(SOCKET Sock, char* lpBuf, int nBufLen, 
		SOCKADDR* lpSockAddr = 0, int* lpSockAddrLen = 0, int nFlags = MSG_NOSIGNAL);

	int IOCtl(SOCKET Sock, long lCommand, u_long* lpArgument);
	int IOCtl(SOCKET Sock, long lCommand, u_long Argument);
	int GetSockOpt(SOCKET Sock, int nLevel, int nOptionName, void* lpOptionValue, int* lpOptionLen);
	int GetSockOpt(SOCKET Sock, int nLevel, int nOptionName, void* lpOptionValue, int nOptionLen);
	int SetSockOpt(SOCKET Sock, int nLevel, int nOptionName, const void* lpOptionValue, int nOptionLen);
	int SetSendTimeOut(SOCKET Sock, int TimeOut);
	int SetRecvTimeOut(SOCKET Sock, int TimeOut);
	int GetSendTimeOut(SOCKET Sock);
	int GetRecvTimeOut(SOCKET Sock);
	int SetKeepAlive(SOCKET Sock, u_long onoff, u_long time = 30*1000);

	int GetPeerName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	int GetSockName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);

	int GetLastError();
	void SetLastError(int nError);

	int GetErrorMessageA(int nError, char* lpszMessage, int nMessageLen);
	int GetErrorMessageW(int nError, wchar_t* lpszMessage, int nMessageLen);
#ifdef UNICODE
#define GetErrorMessage GetErrorMessageW
#else
#define GetErrorMessage GetErrorMessageA
#endif//

/*!
 *	@brief Socket封装.
 *
 *	封装Socket的基本操作
 */
class XSOCKET_API Socket
{
protected:
	SOCKET m_Sock;
public:
	Socket(SOCKET Sock = INVALID_SOCKET):m_Sock(Sock) { }
	~Socket() { }

	inline operator SOCKET() const { return m_Sock; }

	inline bool IsSocket() { 
#if 0
		if(IsSocket(m_Sock)) {
			int OptVal = 0;
			if(GetSockOpt(SO_TYPE, (void*)&OptVal, sizeof OptVal) == SOCKET_ERROR) {
				if(GetLastError() == WSAENOTSOCK) {
					m_Sock = INVALID_SOCKET;
					return false;
				}
			}
			return true;
		}
		return false;
#else
		return XSocket::IsSocket(m_Sock);
#endif//
	}

	inline SOCKET Open(int nSockAf = AF_INET, int nSockType = SOCK_STREAM) { return Attach(XSocket::Open(nSockAf, nSockType, 0)); }
	inline SOCKET Attach(SOCKET Sock) { SOCKET oSock = m_Sock; m_Sock = Sock; return oSock; }
	inline SOCKET Detach() { return Attach(INVALID_SOCKET); }
	inline int ShutDown(int nHow = Both) { return XSocket::ShutDown(m_Sock, nHow); }
	inline int Close() { if (IsSocket()) { return XSocket::Close(Detach()); } return 0; }

	inline SOCKET Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return XSocket::Accept(m_Sock, lpSockAddr, lpSockAddrLen); }
	inline int Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen) { return XSocket::Bind(m_Sock, lpSockAddr, nSockAddrLen); }
	inline int Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen) { return XSocket::Connect(m_Sock, lpSockAddr, nSockAddrLen); }
	inline int Listen(int nConnectionBacklog = 5) { return XSocket::Listen(m_Sock, nConnectionBacklog); }
	inline int Send(const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return XSocket::Send(m_Sock, lpBuf, nBufLen, nFlags); }
	inline int Receive(char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return XSocket::Receive(m_Sock, lpBuf, nBufLen, nFlags); }
	//inline int SyncSend(const char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return SyncSend(m_Sock, lpBuf, nBufLen, nFlags); }
	//inline int SyncReceive(char* lpBuf, int nBufLen, int nFlags = MSG_NOSIGNAL) { return SyncReceive(m_Sock, lpBuf, nBufLen, nFlags); }
	inline int SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags = MSG_NOSIGNAL) 
	{ return XSocket::SendTo(m_Sock, lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags); }
	inline int ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags = MSG_NOSIGNAL)
	{ return XSocket::ReceiveFrom(m_Sock, lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags); }

	inline int GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return XSocket::GetPeerName(m_Sock, lpSockAddr, lpSockAddrLen); }
	inline int GetSockName(SOCKADDR* lpSockAddr, int* lpSockAddrLen) { return XSocket::GetSockName(m_Sock, lpSockAddr, lpSockAddrLen); }

	inline int IOCtl(long lCommand, u_long* lpArgument) { return XSocket::IOCtl(m_Sock, lCommand, lpArgument); }
	inline int IOCtl(long lCommand, u_long Argument)  { return XSocket::IOCtl(m_Sock, lCommand, Argument); }
	inline int GetSockOpt(int nLevel, int nOptionName, void* lpOptionValue, int nOptionLen) 
	{ return XSocket::GetSockOpt(m_Sock, nLevel, nOptionName, lpOptionValue, &nOptionLen); }
	inline int SetSockOpt(int nLevel, int nOptionName, const void* lpOptionValue, int nOptionLen)
	{	return XSocket::SetSockOpt(m_Sock, nLevel, nOptionName, lpOptionValue, nOptionLen); }
	inline int SetSockOpt(int nLevel, int nOptionName, u_long OptionValue)
	{ return XSocket::SetSockOpt(m_Sock, nLevel, nOptionName, &OptionValue, sizeof(OptionValue)); }
	inline int SetSendTimeOut(int TimeOut) { return XSocket::SetSendTimeOut(m_Sock, TimeOut); }
	inline int SetRecvTimeOut(int TimeOut) { return XSocket::SetRecvTimeOut(m_Sock, TimeOut); }
	inline int GetSendTimeOut() { return XSocket::GetSendTimeOut(m_Sock); }
	inline int GetRecvTimeOut() { return XSocket::GetRecvTimeOut(m_Sock); }
	inline int SetKeepAlive(u_long onoff, u_long time = 30*1000) { return XSocket::SetKeepAlive(m_Sock, onoff, time); }

	inline int GetLastError() { return XSocket::GetLastError(); }
	inline void SetLastError(int nError) { XSocket::SetLastError(nError); }
	inline int GetErrorMessageA(int nError, char* lpszMessage, int nMessageLen) { return XSocket::GetErrorMessageA(nError, lpszMessage, nMessageLen); }
	inline int GetErrorMessageW(int nError, wchar_t* lpszMessage, int nMessageLen) { return XSocket::GetErrorMessageW(nError, lpszMessage, nMessageLen); }
};

}

#endif//_H_XSOCKET_H_
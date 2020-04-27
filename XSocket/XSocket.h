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
#ifndef _H_XSOCKET_H_
#define _H_XSOCKET_H_

#include "XSocketDef.h"

namespace XSocket {

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
	/*static u_long H2N(u_long n);
	static u_long N2H(u_long n);
	static u_short H2N(u_short n);
	static u_short N2H(u_short n);*/

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
	static const char* SockAddr2PortStr(const SOCKADDR* lpSockAddr, int nSockAddrLen, char* str, int len);
	static const char* SockAddr2Str(const SOCKADDR* lpSockAddr, int nSockAddrLen, char* str, int len);

	static const char* Url2IpStr(const char* url, char* str, int len);

	static int CreatePairs(SOCKET* sv, int svlen);
	static void ClosePairs(SOCKET* sv, int svlen);
	static inline int CreatePair(int d, int type, int protocol, SOCKET sv[2])
	{
	#ifdef WIN32
		return CreatePairs(sv, 2);
	#else
		return socketpair(d, type, protocol, sv);
	#endif//
	}
	static inline void ClosePair(SOCKET sv[2])
	{
		ClosePairs(sv, 2);
	}
	static int ReadPair(SOCKET Sock, char* lpBuf, int nBufLen);
	static int WritePair(SOCKET Sock, const char* lpBuf, int nBufLen);
	
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
	static int GetAddrType(SOCKET Sock);
	static int SetSendTimeOut(SOCKET Sock, int TimeOut);
	static int SetRecvTimeOut(SOCKET Sock, int TimeOut);
	static int GetSendTimeOut(SOCKET Sock);
	static int GetRecvTimeOut(SOCKET Sock);
	static int SetKeepAlive(SOCKET Sock, u_long onoff, u_long time = 30*1000);
	static int SetBlock(SOCKET Sock);
	static int SetNonBlock(SOCKET Sock);
	static int SetLinger(SOCKET Sock, int onoff, int linger);

	static int GetPeerName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	static int GetSockName(SOCKET Sock, SOCKADDR* lpSockAddr, int* lpSockAddrLen);

	static int GetLastError();
	static void SetLastError(int nError);

	static const char* GetErrorMessage(int nError);
	
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
	inline int SetBlock() { return SetBlock(sock_); }
	inline int SetNonBlock() { return SetNonBlock(sock_); }
	inline int SetLinger(int onoff, int linger) { return SetLinger(sock_, onoff, linger); }
	inline int GetAddrType() { return GetAddrType(sock_); }
};

#ifndef PRINTLASTERROR
#define PRINTLASTERROR XSocket::Socket::PrintLastError
#endif

}

#endif//_H_XSOCKET_H_
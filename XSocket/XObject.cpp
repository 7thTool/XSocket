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
#include "XSocketEx.h"

#ifdef WIN32
#ifndef SIO_UDP_CONNRESET
// MS Transport Provider IOCTL to control
// reporting PORT_UNREACHABLE messages
// on UDP sockets via recv/WSARecv/etc.
// Path TRUE in input buffer to enable (default if supported),
// FALSE to disable.
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
#endif//SIO_UDP_CONNRESET
#endif//

namespace XSocket {

std::future<struct addrinfo*> SocketEx::AsyncGetAddrInfo( const char *hostname, const char *service, const struct addrinfo *hints)
{
	return std::async( //std::launch::async|std::launch::deferred,
	//return ThreadPool::Inst().Post(
		[hostname, service, hints] {
			struct addrinfo *res = nullptr;
			GetAddrInfo(hostname, service, hints, &res);
			return res;
		});
#if 0
		std::future_status status;
		do {
			status = result.wait_for(std::chrono::milliseconds(10));
			switch (status)
			{
			case std::future_status::ready:
				PRINTF("AsyncGetAddrInfo Ready...");
				break;
			case std::future_status::timeout:
				PRINTF("AsyncGetAddrInfo Wait...");
				break;
			case std::future_status::deferred:
				PRINTF("AsyncGetAddrInfo Deferred...");
				break;
			default:
				break;
			}

		} while (status != std::future_status::ready);
		struct addrinfo *ai_result = result.get();
#endif //
	   //return result;
}

SocketEx::SocketEx()
:Base()
,role_(SOCKET_ROLE_NONE)
#ifdef _DEBUG
,flags_(SOCKET_FLAG_DEBUG)
#else
,flags_(SOCKET_FLAG_DEBUG)
#endif
,event_(0)
{
#ifdef _DEBUG
	PRINTF("new Socket %p", this);
#endif
}

SocketEx::~SocketEx()
{
	//ASSERT(!IsSocket());
#ifdef _DEBUG
	PRINTF("delete Socket %p %u", this, sock_);
	role_ = SOCKET_ROLE_NONE;
	event_ = 0;
#endif
}

SOCKET SocketEx::Open(int nSockAf, int nSockType, int nSockProtocol)
{
	int nRole = SOCKET_ROLE_NONE;
	SOCKET Sock = Base::Create(nSockAf, nSockType, nSockProtocol);
	if ((nSockAf==AF_INET&&nSockType==SOCK_DGRAM)) {
		nRole = SOCKET_ROLE_WORK;
#ifdef WIN32
		//解决UDP 10054 ECONNRESET 错误
		DWORD dwBytesReturned = 0;
		BOOL bNewBehavior = FALSE;
		DWORD status;
		// disable  new behavior using
		// IOCTL: SIO_UDP_CONNRESET
		status = WSAIoctl(Sock, SIO_UDP_CONNRESET,
			&bNewBehavior, sizeof(bNewBehavior),
			NULL, 0, &dwBytesReturned,
			NULL, NULL);
		if (SOCKET_ERROR == status) {
			int err = GetLastError();
			if (EWOULDBLOCK == err) {
				
			} else {
				PRINTF("WSAIoctl(SIO_UDP_CONNRESET) Error: %d", err);
			}
		}
#endif//
	}
	Attach(Sock, nRole);
	return Sock;
}

SOCKET SocketEx::Attach(SOCKET Sock, int Role)
{
	SOCKET oSock = Base::Attach(Sock);
	if(Role != SOCKET_ROLE_NONE) {
		OnRole(Role);
	}
	role_ = Role;
	return oSock;
}

SOCKET SocketEx::Detach()
{
	return Attach(INVALID_SOCKET,SOCKET_ROLE_NONE);
}

int SocketEx::ShutDown(int nHow)
{
	return Base::ShutDown(nHow);
}

int SocketEx::Close()
{
	if(IsSocket()) {
		if(IsDebug()) {
			PRINTF("Close Socket %p %u", this, (SOCKET)*this);
		}
		event_ = 0;
		return Base::Close(Detach());
	}
	return 0;
}

// int SocketEx::Bind(const char* lpszHostAddress, unsigned short nHostPort)
// {
// 	SOCKADDR_IN sockAddr = {0};
// 	if (lpszHostAddress == NULL) {
// 		sockAddr.sin_addr.s_addr = H2N((u_long)INADDR_ANY);
// 	} else {
// 		sockAddr.sin_addr.s_addr = Ip2N(Url2Ip((char*)lpszHostAddress));
// 		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
// 			SetLastError(EINVAL);
// 			return SOCKET_ERROR;
// 		}
// 	}
// 	sockAddr.sin_family = AF_INET;
// 	sockAddr.sin_port = H2N((u_short)nHostPort);
// 	return Bind((SOCKADDR*)&sockAddr, sizeof(sockAddr));
// }

int SocketEx::Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if(IsDebug()) {
		PRINTF("Bind Socket %p %u", this, (SOCKET)*this);
	}
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	int rlt = Base::Bind(lpSockAddr,nSockAddrLen);
	return rlt;
}

int SocketEx::Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if(IsDebug()) {
		PRINTF("Connect Socket %p %u", this, (SOCKET)*this);
	}
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	OnRole(SOCKET_ROLE_CONNECT);
	role_ = SOCKET_ROLE_CONNECT;
	event_ |= FD_CONNECT;
	SetNonBlock();//设为非阻塞模式
	return Base::Connect(lpSockAddr, nSockAddrLen);
}

int SocketEx::Listen(int nConnectionBacklog)
{
	if(IsDebug()) {
		PRINTF("Listen Socket %p %u", this, (SOCKET)*this);
	}
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	OnRole(SOCKET_ROLE_LISTEN);
	role_ = SOCKET_ROLE_LISTEN;
	event_ |= FD_ACCEPT;
	SetNonBlock();//设为非阻塞模式
	return Base::Listen(nConnectionBacklog);
}

// SOCKET SocketEx::Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
// {
// 	return Base::Accept(lpSockAddr,lpSockAddrLen);
// }

// int SocketEx::Send(const char* lpBuf, int nBufLen, int nFlags)
// {
// 	return Base::Send(lpBuf, nBufLen, nFlags);
// }

// int SocketEx::Receive(char* lpBuf, int nBufLen, int nFlags)
// {
// 	return Base::Receive(lpBuf, nBufLen, nFlags);
// }

// int SocketEx::SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
// {
// 	return Base::SendTo(lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags);
// }

// int SocketEx::ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags)
// {
// 	return Base::ReceiveFrom(lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags);
// }

void SocketEx::OnRole(int nRole)
{
	if(IsDebug()) {
		PRINTF("(%p %u)::OnRole role=%d-%d flags=%d event=%d", this, (SOCKET)*this, nRole, role_, flags_, event_);
	}
}

void SocketEx::OnAttachService(Service* pSvr)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnAttachService", pSvr, this, (SOCKET)*this);
	}
}

void SocketEx::OnDetachService(Service* pSvr)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnDetachService", pSvr, this, (SOCKET)*this);
	}
}

inline bool IsNBErrorCode(int nErrorCode)
{
	switch (nErrorCode)
	{
	case 0:
		return true;
		break;
#ifdef WIN32
	case WSAEWOULDBLOCK:
	case WSA_IO_PENDING:
		return true;
		break;
#else
	case EWOULDBLOCK:
		return true;
		break;
	case EINTR:
		return true;
		break;
#endif //
	default:
		break;
	}
	return false;
}

void SocketEx::OnIdle()
{
	
}

void SocketEx::OnReceive(int nErrorCode)
{
	if(!IsNBErrorCode(nErrorCode)) {
		if(IsDebug()) {
			PRINTF("(%p %p %u)::OnReceive:%d", Service::service(), this, (SOCKET)*this, nErrorCode);
		}
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnReceive(const char* lpBuf, int nBufLen, int nFlags)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnReceive:%d %.*s", Service::service(), this, (SOCKET)*this, nBufLen, std::min<>(nBufLen,19), lpBuf);
	}
}

void SocketEx::OnReceiveFrom(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
{
	if(IsDebug()) {
		char str[64] = {0};
		PRINTF("(%p %p %u)::OnReceiveFrom(%s):%d %.*s", Service::service(), this, (SOCKET)*this, SockAddr2Str(lpSockAddr,nSockAddrLen,str,64), nBufLen, std::min<>(nBufLen,19), lpBuf);
	}
}

void SocketEx::OnSend(int nErrorCode)
{
	if(!IsNBErrorCode(nErrorCode)) {
		if(IsDebug()) {
			PRINTF("(%p %p %u)::OnSend:%d", Service::service(), this, (SOCKET)*this, nErrorCode);
		}
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnSend(const char* lpBuf, int nBufLen, int nFlags)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnSend:%d %.*s", Service::service(), this, (SOCKET)*this, nBufLen, std::min<>(nBufLen,19), lpBuf);
	}
}

void SocketEx::OnSendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
{
	if(IsDebug()) {
		char str[64] = {0};
		PRINTF("(%p %p %u)::OnSendTo(%s):%d %.*s", Service::service(), this, (SOCKET)*this, SockAddr2Str(lpSockAddr,nSockAddrLen,str,64), nBufLen, std::min<>(nBufLen,19), lpBuf);
	}
}

void SocketEx::OnOOB(int nErrorCode)
{
	if(!IsNBErrorCode(nErrorCode)) {
		if(IsDebug()) {
			PRINTF("(%p %p %u)::OnOOB:%d", Service::service(), this, (SOCKET)*this, nErrorCode);
		}
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnOOB(const char* lpBuf, int nBufLen, int nFlags)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnOOB:%d %.*s", Service::service(), this, (SOCKET)*this, nBufLen, std::min<>(nBufLen,19), lpBuf);
	}
}

void SocketEx::OnAccept(int nErrorCode)
{
	if(!IsNBErrorCode(nErrorCode)) {
		if(IsDebug()) {
			PRINTF("(%p %p %u)::OnAccept:%d", Service::service(), this, (SOCKET)*this, nErrorCode);
		}
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnAccept(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if(IsDebug()) {
		char str[64] = {0};
		PRINTF("(%p %p %u)::OnAccept(%s):%u", Service::service(), this, (SOCKET)*this, lpSockAddr?SockAddr2Str(lpSockAddr,nSockAddrLen,str,64):"", Sock);
	}
}

void SocketEx::OnConnect(int nErrorCode)
{
	if(!IsNBErrorCode(nErrorCode)) {
		if(IsDebug()) {
			PRINTF("(%p %p %u)::OnConnect:%d", Service::service(), this, (SOCKET)*this, nErrorCode);
		}
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnClose(int nErrorCode)
{
	if(IsDebug()) {
		PRINTF("(%p %p %u)::OnClose:%d %s", Service::service(), this, (SOCKET)*this, nErrorCode, GetErrorMessage(nErrorCode));
	}
}

///
///Service
///

thread_local Service* s_thread_service_ = nullptr;

Service* Service::service()
{
	return s_thread_service_;
}

Service::Service():stop_flag_(true),idle_flag_(true),notify_flag_(false),wait_timeout_(0)
{
	
}

bool Service::OnInit()
{
	s_thread_service_ = this;
#ifdef _DEBUG
	PRINTF("thread id="I64U", service=%p", std::this_thread::get_id(), s_thread_service_);
#endif
	return true;
}

}


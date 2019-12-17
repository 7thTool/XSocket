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

SocketEx::SocketEx()
:Socket(),role_(SOCKET_ROLE_NONE),event_(0)
{
	PRINTF("new Socket %p\n", this);
}

SocketEx::~SocketEx()
{
	PRINTF("delete Socket %p\n", this);
	ASSERT(!IsSocket());
	role_ = SOCKET_ROLE_NONE;
	event_ = 0;
}

SOCKET SocketEx::Open(int nSockAf, int nSockType)
{
	int nRole = SOCKET_ROLE_NONE;
	SOCKET Sock = Socket::Open(nSockAf, nSockType, 0);
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
				PRINTF("WSAIoctl(SIO_UDP_CONNRESET) Error: %d\n", err);
			}
		}
#endif//
	}
	return Attach(Sock, nRole);
}

SOCKET SocketEx::Attach(SOCKET Sock, int Role)
{
	SOCKET oSock = Socket::Attach(Sock);
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
	return Socket::ShutDown(nHow);
}

int SocketEx::Close()
{
	if(IsSocket()) {
		PRINTF("Close Socket %p %d\n", this, (SOCKET)*this);
		event_ = 0;
		return Socket::Close(Detach());
	}
	return 0;
}

SOCKET SocketEx::Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
	return Socket::Accept(lpSockAddr,lpSockAddrLen);
}

int SocketEx::Bind(const char* lpszHostAddress, unsigned short nHostPort)
{
	SOCKADDR_IN sockAddr = {0};
	if (lpszHostAddress == NULL) {
		sockAddr.sin_addr.s_addr = H2N((u_long)INADDR_ANY);
	} else {
		sockAddr.sin_addr.s_addr = Ip2N(Url2Ip((char*)lpszHostAddress));
		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
			SetLastError(EINVAL);
			return SOCKET_ERROR;
		}
	}
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = H2N((u_short)nHostPort);
	return Bind((SOCKADDR*)&sockAddr, sizeof(sockAddr));
}

int SocketEx::Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	PRINTF("Bind Socket %p %d\n", this, (SOCKET)*this);
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	int rlt = Socket::Bind(lpSockAddr,nSockAddrLen);
	return rlt;
}

int SocketEx::Connect(const char* lpszHostAddress, unsigned short nHostPort)
{
	SOCKADDR_IN sockAddr = {0};
	if (lpszHostAddress == NULL) {
		sockAddr.sin_addr.s_addr = H2N((u_long)INADDR_ANY);
	} else {
		sockAddr.sin_addr.s_addr = Ip2N(Url2Ip((char*)lpszHostAddress));
		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
			//SetLastError(EINVAL);
			//return SOCKET_ERROR;
		}
	}
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = H2N((u_short)nHostPort);
	return Connect((SOCKADDR*)&sockAddr, sizeof(sockAddr));
}

int SocketEx::Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	PRINTF("Connect Socket %p %d\n", this, (SOCKET)*this);
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	OnRole(SOCKET_ROLE_CONNECT);
	role_ = SOCKET_ROLE_CONNECT;
	event_ |= FD_CONNECT;
#ifdef WIN32
	IOCtl(FIONBIO, 1);//设为非阻塞模式
#else
	int flags = IOCtl(F_GETFL,(u_long)0); 
	IOCtl(F_SETFL, (u_long)(flags|O_NONBLOCK)); //设为非阻塞模式
	//IOCtl(F_SETFL, (u_long)(flags&~O_NONBLOCK)); //设为阻塞模式
#endif//
	int rlt = Socket::Connect(lpSockAddr, nSockAddrLen);
	//让用户在OnConnect或者OnClose响应
	//if (rlt==0) {
	//	event_ &= ~FD_CONNECT;
	//}
	return rlt;
}

int SocketEx::Listen(int nConnectionBacklog)
{
	PRINTF("Listen Socket %p %d\n", this, (SOCKET)*this);
	//SectionLocker Lock(&m_Section);
	ASSERT(IsSocket());
	OnRole(SOCKET_ROLE_LISTEN);
	role_ = SOCKET_ROLE_LISTEN;
	event_ |= FD_ACCEPT;
#ifdef WIN32
	IOCtl(FIONBIO, 1);//设为非阻塞模式
#else
	int flags = IOCtl(F_GETFL,(u_long)0); 
	IOCtl(F_SETFL, (u_long)(flags|O_NONBLOCK)); //设为非阻塞模式
	//IOCtl(F_SETFL, (u_long)(flags&~O_NONBLOCK)); //设为阻塞模式
#endif//
	return Socket::Listen(nConnectionBacklog);
}

int SocketEx::Send(const char* lpBuf, int nBufLen, int nFlags)
{
	return Socket::Send(lpBuf, nBufLen, nFlags);
}

int SocketEx::Receive(char* lpBuf, int nBufLen, int nFlags)
{
	return Socket::Receive(lpBuf, nBufLen, nFlags);
}

int SocketEx::SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
{
	return Socket::SendTo(lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags);
}

int SocketEx::ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags)
{
	return Socket::ReceiveFrom(lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags);
}

void SocketEx::OnRole(int nRole)
{
	
}

void SocketEx::OnAttachService(Service* pSvr)
{
	PRINTF("(%p %p %d)::OnAttachService\n", pSvr, this, (SOCKET)*this);
}

void SocketEx::OnDetachService(Service* pSvr)
{
	PRINTF("(%p %p %d)::OnDetachService\n", pSvr, this, (SOCKET)*this);
}

void SocketEx::OnIdle(int nErrorCode)
{
	
}

void SocketEx::OnReceive(int nErrorCode)
{
	if(nErrorCode) {
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnReceive(const char* lpBuf, int nBufLen, int nFlags)
{
	PRINTF("(%p %p %d)::OnReceive:%.*s\n", Service::service(), this, (SOCKET)*this, nBufLen, lpBuf);
}

void SocketEx::OnReceiveFrom(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
{
	PRINTF("(%p %p %d)::OnReceiveFrom(%s:%d): %.*s\n", Service::service(), this, (SOCKET)*this, N2Ip(Addr2Ip(lpSockAddr,nSockAddrLen)), N2H(Addr2Port(lpSockAddr,nSockAddrLen)), nBufLen, lpBuf);
}

void SocketEx::OnSend(int nErrorCode)
{
	if(nErrorCode) {
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnSend(const char* lpBuf, int nBufLen, int nFlags)
{
	PRINTF("(%p %p %d)::OnSend:%.*s\n", Service::service(), this, (SOCKET)*this, nBufLen, lpBuf);
}

void SocketEx::OnSendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags)
{
	PRINTF("(%p %p %d)::OnSendTo(%s:%d):%.*s\n", Service::service(), this, (SOCKET)*this, N2Ip(Addr2Ip(lpSockAddr,nSockAddrLen)), N2H(Addr2Port(lpSockAddr,nSockAddrLen)), nBufLen, lpBuf);
}

void SocketEx::OnOOB(int nErrorCode)
{
	if(nErrorCode) {
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnOOB(const char* lpBuf, int nBufLen, int nFlags)
{
	PRINTF("(%p %p %d)::OnOOB:%.*s\n", Service::service(), this, (SOCKET)*this, nBufLen, lpBuf);
}

void SocketEx::OnAccept(int nErrorCode)
{
	if(nErrorCode) {
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnAccept(const SOCKADDR* lpSockAddr, int nSockAddrLen, SOCKET Sock)
{
	PRINTF("(%p %p %d)::OnAccept:%d\n", Service::service(), this, (SOCKET)*this, Sock);
}

void SocketEx::OnConnect(int nErrorCode)
{
	PRINTF("(%p %p %d)::OnConnect:%d\n", Service::service(), this, (SOCKET)*this, nErrorCode);
	if(nErrorCode) {
		Trigger(FD_CLOSE,nErrorCode);
	}
}

void SocketEx::OnClose(int nErrorCode)
{
#ifdef _DEBUG
	char szError[1024] = {0};
	GetErrorMessage(nErrorCode,szError,1023);
	PRINTF("(%p %p %d)::OnClose:%d %s\n", Service::service(), this, (SOCKET)*this, nErrorCode, szError);
#else
	PRINTF("(%p %p %d)::OnClose:%d\n", Service::service(), this, (SOCKET)*this, nErrorCode);
#endif//
	//ASSERT(!IsSocket());
	// if(IsSocket()) {
	// 	Close();
	// }
}

///
///Service
///

thread_local Service* s_thread_service_ = nullptr;

Service* Service::service()
{
	return s_thread_service_;
}

Service::Service():stop_flag_(true)
{
	
}

bool Service::OnInit()
{
	PRINTF("thread id=%d, service=0x%p\n", std::this_thread::get_id(), s_thread_service_);
	s_thread_service_ = this;
	return true;
}

}


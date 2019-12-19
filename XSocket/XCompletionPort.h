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

#ifndef _H_XIOCPSOCKETEX_H_
#define _H_XIOCPSOCKETEX_H_

#include "XSocketEx.h"
#include <MSWSock.h>

namespace XSocket {

#define IOCP_OPERATION_EXIT DWORD(-1)
#define IOCP_OPERATION_TRYRECEIVE DWORD(-2)
#define IOCP_OPERATION_TRYSEND DWORD(-3)
#define IOCP_OPERATION_TRYACCEPT DWORD(-4)

/*!
 *	@brief CompletionPort OVERLAPPED 定义.
 *
 *	ERROR_PORT_UNREACHABLE	1234	No service is operating at the destination network endpoint on the remote system.
 *	ERROR_OPERATION_ABORTED	995		The I/O operation has been aborted because of either a thread exit or an application request.
 */
enum 
{
	IOCP_OPERATION_NONE = 0,
	IOCP_OPERATION_ACCEPT,
	IOCP_OPERATION_CONNECT,
	IOCP_OPERATION_RECEIVE,
	IOCP_OPERATION_SEND,
};
typedef struct _PER_IO_OPERATION_DATA
{ 
	WSAOVERLAPPED	Overlapped;
	WSABUF			Buffer;
	byte			OperationType;
	union 
	{
		DWORD		Flags;
		SOCKET		Sock; //Accept
	};
	union
	{
		DWORD		NumberOfBytesCompleted;
		DWORD		NumberOfBytesReceived;
		DWORD		NumberOfBytesSended;
	};
}PER_IO_OPERATION_DATA, *LPPER_IO_OPERATION_DATA;

/*!
 *	@brief CompletionPortSocket 模板定义.
 *
 *	封装CompletionPortSocket
 */
template<class TSocketSet, class TBase = SocketEx>
class CompletionPortSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef TSocketSet SocketSet;
protected:
	union 
	{
		struct 
		{
			LPFN_ACCEPTEX lpfnAcceptEx;
			LPFN_GETACCEPTEXSOCKADDRS lpfnGetAcceptExSockaddrs;
			char AccpetBuf[1];
		};
		struct 
		{
			LPFN_CONNECTEX lpfnConnectEx;
			PER_IO_OPERATION_DATA m_SendOverlapped;
		};
		char Reserved[sizeof(PER_IO_OPERATION_DATA) + sizeof(LPFN_CONNECTEX)];
	};
	PER_IO_OPERATION_DATA m_ReceiveOverlapped;
public:
	static SocketSet* service() { return dynamic_cast<SocketSet*>(SocketSet::service()); }

	CompletionPortSocketT():Base()
	{
		memset(&Reserved,0,sizeof(Reserved));
		memset(&m_ReceiveOverlapped,0,sizeof(PER_IO_OPERATION_DATA));
	}

	virtual ~CompletionPortSocketT()
	{
		
	}
	
	SOCKET Open(int nSockAf = AF_INET, int nSockType = SOCK_STREAM)
	{
		SOCKET Sock = WSASocket(nSockAf, nSockType, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		DWORD dwBytes = 0;
		do {
			// 获取AcceptEx函数指针
			dwBytes = 0;
			GUID GuidAcceptEx = WSAID_ACCEPTEX;
			if (0 != WSAIoctl(Sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
							&GuidAcceptEx, sizeof(GuidAcceptEx),
							&lpfnAcceptEx, sizeof(lpfnAcceptEx), &dwBytes, NULL, NULL)) {
				PRINTF("WSAIoctl AcceptEx is failed. Error=%d\n", GetLastError());
				break;
			}
			// 获取GetAcceptExSockAddrs函数指针
			dwBytes = 0;
			GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
			if (0 != WSAIoctl(Sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
							&GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs),
							&lpfnGetAcceptExSockaddrs, sizeof(lpfnGetAcceptExSockaddrs), &dwBytes, NULL, NULL)) {
				PRINTF("WSAIoctl GetAcceptExSockaddrs is failed. Error=%d\n", GetLastError());
				break;
			}
			//获得ConnectEx 函数的指针
			dwBytes = 0;
			GUID GuidConnectEx = WSAID_CONNECTEX;
			if (SOCKET_ERROR == WSAIoctl(Sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
				&GuidConnectEx, sizeof(GuidConnectEx ),
				&lpfnConnectEx, sizeof (lpfnConnectEx), &dwBytes, 0, 0)) {
				PRINTF("WSAIoctl ConnectEx is failed. Error=%d\n", GetLastError());
				break;
			}
		} while(false);
		if(!lpfnAcceptEx || !lpfnGetAcceptExSockaddrs || !lpfnConnectEx) {
			XSocket::Socket::Close(Sock);
			return INVALID_SOCKET;
		}
		int nRole = SOCKET_ROLE_NONE;
		if ((nSockAf==AF_INET&&nSockType==SOCK_DGRAM)) {
			nRole = SOCKET_ROLE_WORK;
		}
		return Attach(Sock, nRole);
	}

	int Connect(const char* lpszHostAddress, unsigned short nHostPort)
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

	int Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
	{
		ASSERT(IsSocket());

		DWORD dwBytes = 0;
		do {
			//获得ConnectEx 函数的指针
			dwBytes = 0;
			GUID GuidConnectEx = WSAID_CONNECTEX;
			if (SOCKET_ERROR == WSAIoctl((SOCKET)*this, SIO_GET_EXTENSION_FUNCTION_POINTER,
				&GuidConnectEx, sizeof(GuidConnectEx ),
				&lpfnConnectEx, sizeof (lpfnConnectEx), &dwBytes, 0, 0)) {
				PRINTF("WSAIoctl ConnectEx is failed. Error=%d\n", GetLastError());
				break;
			}
		} while(false);
		if(!lpfnConnectEx) {
			return SOCKET_ERROR;
		}

		OnRole(SOCKET_ROLE_CONNECT);
		role_ = SOCKET_ROLE_CONNECT;
		event_ |= FD_CONNECT;
		IOCtl(FIONBIO, 1);//设为非阻塞模式

		//MSDN说The parameter s is an unbound or a listening socket，
		//还是诡异两个字connect操作干嘛要绑定？不知道，没人给解释，那绑定就对了，那么绑哪个？
		//最好把你的地址结构像下面这样设置
		switch (lpSockAddr->sa_family)
		{
		case AF_INET:
		{
			SOCKADDR_IN addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(0);
			addr.sin_addr.s_addr = htonl(ADDR_ANY);
			//为什么端口这个地方用0，原因很简单，你去查查MSDN，这样表示他会在1000-4000这个范围（可能记错，想了解的话去查MSDN）找一个没被用到的port，
			//这样的话最大程度保证你bind的成功，然后再把socket句柄丢给IOCP，然后调用ConnectEx这样就会看到熟悉的WSA_IO_PENDING了！
			Bind((const SOCKADDR*)&addr,sizeof(SOCKADDR_IN));
		}
		break;
		case AF_INET6:
		break;
		default:
		ASSERT(0);
		break;
		}
		
		PER_IO_OPERATION_DATA* pOverlapped = &m_SendOverlapped;
		memset(&pOverlapped->Overlapped, 0, sizeof(WSAOVERLAPPED));
		pOverlapped->Buffer.buf	= NULL;
		pOverlapped->Buffer.len	= 0;
		pOverlapped->Flags = 0;
		pOverlapped->OperationType = IOCP_OPERATION_CONNECT;
		pOverlapped->NumberOfBytesSended = 0;
		if(lpfnConnectEx((SOCKET)*this, 
			lpSockAddr, 
			nSockAddrLen, 
			pOverlapped->Buffer.buf,
			pOverlapped->Buffer.len,
			(LPDWORD)&pOverlapped->NumberOfBytesSended, 
			&pOverlapped->Overlapped)) {
			ASSERT(0);
			return 0;
		} else {
			//int nError = GetLastError();
			//PRINTF("ConnectEx is failed. Error=%d\n", nError);
		}
		return SOCKET_ERROR;
	}

	int Listen(int nConnectionBacklog = 5)
	{
		int ret = Base::Listen(nConnectionBacklog);
		RemoveSelect(FD_ACCEPT);
		return ret;
	}

	SOCKET Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
	{
		DWORD dwBytes = 0;
		do {
			// 获取AcceptEx函数指针
			dwBytes = 0;
			GUID GuidAcceptEx = WSAID_ACCEPTEX;
			if (0 != WSAIoctl((SOCKET)*this, SIO_GET_EXTENSION_FUNCTION_POINTER,
							&GuidAcceptEx, sizeof(GuidAcceptEx),
							&lpfnAcceptEx, sizeof(lpfnAcceptEx), &dwBytes, NULL, NULL)) {
				PRINTF("WSAIoctl AcceptEx is failed. Error=%d\n", GetLastError());
				break;
			}
			// 获取GetAcceptExSockAddrs函数指针
			dwBytes = 0;
			GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
			if (0 != WSAIoctl((SOCKET)*this, SIO_GET_EXTENSION_FUNCTION_POINTER,
							&GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs),
							&lpfnGetAcceptExSockaddrs, sizeof(lpfnGetAcceptExSockaddrs), &dwBytes, NULL, NULL)) {
				PRINTF("WSAIoctl GetAcceptExSockaddrs is failed. Error=%d\n", GetLastError());
				break;
			}
		} while(false);
		if(!lpfnAcceptEx || !lpfnGetAcceptExSockaddrs) {
			return INVALID_SOCKET;
		}

		//为即将到来的Client连接事先创建好Socket，异步连接需要事先将此Socket备下，再行连接
		SOCKET Sock = XSocket::Socket::Open(AF_INET, SOCK_STREAM, 0);
		if(Sock == INVALID_SOCKET) {
			return INVALID_SOCKET;
		}

		PER_IO_OPERATION_DATA* pOverlapped = &m_ReceiveOverlapped;
		memset(&pOverlapped->Overlapped, 0, sizeof(WSAOVERLAPPED));
		pOverlapped->Buffer.buf	= AccpetBuf; //这个不能为空, 应使其不小于16，因为SOCKADDR_IN大小影响
		pOverlapped->Buffer.len	= 0; //0表只连不接收、连接到来->请求完成，否则连接到来+任意长数据到来->请求完成
		pOverlapped->OperationType = IOCP_OPERATION_ACCEPT;
		pOverlapped->Sock = Sock;
		pOverlapped->NumberOfBytesReceived = 0;
		//调用AcceptEx函数，地址长度需要在原有的上面加上16个字节
		int nAccept = lpfnAcceptEx((SOCKET)*this, pOverlapped->Sock,
			pOverlapped->Buffer.buf, pOverlapped->Buffer.len, 
			sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, 
			&pOverlapped->NumberOfBytesReceived, &(pOverlapped->Overlapped));
		if(nAccept == 0) {
			if(WSAGetLastError() != ERROR_IO_PENDING) {
				DWORD dwError =  GetLastError();
				PRINTF("WSAIoctl AcceptEx is failed. Error=%d\n",dwError);
				XSocket::Socket::Close(Sock);
				SetLastError(dwError);
				return INVALID_SOCKET;
			}
		}
		return nAccept;
	}

	int Send(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		ASSERT(m_SendOverlapped.NumberOfBytesSended >= m_SendOverlapped.Buffer.len);
		PER_IO_OPERATION_DATA* pOverlapped = &m_SendOverlapped;
		memset(&pOverlapped->Overlapped, 0, sizeof(WSAOVERLAPPED));
		pOverlapped->Buffer.buf	= (char*)lpBuf;
		pOverlapped->Buffer.len	= nBufLen; 
		pOverlapped->Flags = nFlags;
		pOverlapped->OperationType = IOCP_OPERATION_SEND;
		pOverlapped->NumberOfBytesSended = 0;
		int nSend = WSASend((SOCKET)*this, 
			&pOverlapped->Buffer, 
			1, 
			(LPDWORD)&pOverlapped->NumberOfBytesSended, 
			(DWORD)pOverlapped->Flags, 
			&pOverlapped->Overlapped,
			NULL);
		if(nSend == 0) {
			return SOCKET_ERROR;
		}
		return nSend;
	}

	int Receive(char* lpBuf, int nBufLen, int nFlags = 0)
	{
		PER_IO_OPERATION_DATA* pOverlapped = &m_ReceiveOverlapped;
		memset(&pOverlapped->Overlapped,0,sizeof(WSAOVERLAPPED));
		pOverlapped->Buffer.buf = lpBuf;
		pOverlapped->Buffer.len = nBufLen;
		pOverlapped->Flags = nFlags;
		pOverlapped->OperationType = IOCP_OPERATION_RECEIVE;
		pOverlapped->NumberOfBytesReceived = 0;
		int nRecv = WSARecv((SOCKET)*this, 
			&pOverlapped->Buffer, 
			1, 
			(LPDWORD)&pOverlapped->NumberOfBytesReceived, 
			(LPDWORD)&pOverlapped->Flags, 
			&pOverlapped->Overlapped,
			NULL);
		if(nRecv == 0) {
			return SOCKET_ERROR;
		}
		return nRecv;
	}

	inline void Select(int lEvent) {  
		int lAsyncEvent = 0;
		if(!(event_ & FD_READ) && (lEvent & FD_READ)) {
			lAsyncEvent |= FD_READ;
			//PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYRECEIVE, (ULONG_PTR)this, &m_ReceiveOverlapped.Overlapped);
		}
		if(!(event_ & FD_WRITE) && (lEvent & FD_WRITE)) {
			lAsyncEvent |= FD_WRITE;
			//PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYSEND, (ULONG_PTR)this, &m_SendOverlapped.Overlapped);
		}
		if(!(event_ & FD_ACCEPT) && (lEvent & FD_ACCEPT)) {
			lAsyncEvent |= FD_ACCEPT;
			//PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYACCPET, (ULONG_PTR)this, &m_ReceiveOverlapped.Overlapped);
		}
		Base::Select(lEvent);
		if(lAsyncEvent & FD_READ) {
			Trigger(FD_READ, 0);
		}
		if(lAsyncEvent & FD_WRITE) {
			Trigger(FD_WRITE, 0);
		}
		if(lAsyncEvent & FD_ACCEPT) {
			Trigger(FD_ACCEPT, 0);
		}
	}
};

/*!
 *	@brief CompletionPortSocketSet 模板定义.
 *
 *	封装CompletionPortSocketSet，实现对CompletionPort模型封装，最多管理uFD_SETSize数Socket
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class CompletionPortSocketSetT : public SocketSetT<TService,TSocket,uFD_SETSize>
{
	typedef SocketSetT<TService,TSocket,uFD_SETSize> Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
protected:
	HANDLE m_hIocp;
public:
	CompletionPortSocketSetT()
	{
		SYSTEM_INFO SystemInfo = {0};
		GetSystemInfo(&SystemInfo);
		m_hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, SystemInfo.dwNumberOfProcessors);
		ASSERT(m_hIocp!=INVALID_HANDLE_VALUE);
	}

	~CompletionPortSocketSetT()
	{
		if(m_hIocp!=INVALID_HANDLE_VALUE) {
			CloseHandle(m_hIocp);
			m_hIocp = INVALID_HANDLE_VALUE;
		}
	}

	void Stop()
	{
		if(m_hIocp!=INVALID_HANDLE_VALUE) {
			PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_EXIT, 0, NULL);
		}
		Base::Stop();
	}

	inline void AsyncSelect(int pos, int evt) {
		if(evt & FD_READ) {
			PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYRECEIVE, (ULONG_PTR)(pos + 1), NULL);
		}
		if(evt & FD_WRITE) {
			PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYSEND, (ULONG_PTR)(pos + 1), NULL);
		}
		if(evt & FD_ACCEPT) {
			PostQueuedCompletionStatus(m_hIocp, IOCP_OPERATION_TRYACCEPT, (ULONG_PTR)(pos + 1), NULL);
		}
	}
	
	int AddSocket(std::shared_ptr<Socket> sock_ptr, int evt = 0)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]==NULL) {
				if (sock_ptr) {
					sock_count_++;
					sock_ptrs_[i] = sock_ptr;
					sock_ptr->AttachService(this);
					HANDLE hIocp = CreateIoCompletionPort((HANDLE)(SOCKET)*sock_ptr, m_hIocp, (ULONG_PTR)(i + 1), 0);
					ASSERT(hIocp);
					if (hIocp != INVALID_HANDLE_VALUE) {
						PRINTF("CreateIoCompletionPort: %ld by %ld\n", hIocp, m_hIocp);
					} else {
						PRINTF("CreateIoCompletionPort Error:%d\n", ::GetLastError());
					}
					AsyncSelect(i, evt);
					return i;
				} else {
					//测试可不可以增加Socket，返回true表示可以增加
					return i;
				}
				break;
			}
		}
		return -1;
	}

protected:
	//
	virtual void OnRunOnce()
	{
		Base::OnRunOnce();

		// 第1种情况:
		// If the function dequeues a completion packet for a successful I/O operation from the completion port, the return value is nonzero. The function stores information in the variables pointed to by the lpNumberOfBytesTransferred, lpCompletionKey, and lpOverlapped parameters.
		// 如果函数从完成端口取出一个成功I/O操作的完成包，返回值为非0。函数在指向lpNumberOfBytesTransferred, lpCompletionKey, and lpOverlapped的参数中存储相关信息。

		// 第2种情况:
		// If *lpOverlapped is NULL and the function does not dequeue a completion packet from the completion port, the return value is zero. The function does not store information in the variables pointed to by the lpNumberOfBytesTransferred and lpCompletionKey parameters. To get extended error information, call GetLastError. If the function did not dequeue a completion packet because the wait timed out, GetLastError returns WAIT_TIMEOUT. 
		// 如果 *lpOverlapped为空并且函数没有从完成端口取出完成包，返回值则为0。函数则不会在lpNumberOfBytes and lpCompletionKey所指向的参数中存储信息。调用GetLastError可以得到一个扩展错误信息。如果函数由于等待超时而未能出列完成包，GetLastError返回WAIT_TIMEOUT.

		// 第3种情况:
		// If *lpOverlapped is not NULL and the function dequeues a completion packet for a failed I/O operation from the completion port, the return value is zero. The function stores information in the variables pointed to by lpNumberOfBytesTransferred, lpCompletionKey, and lpOverlapped. To get extended error information, call GetLastError
		// 如果 *lpOverlapped不为空并且函数从完成端口出列一个失败I/O操作的完成包，返回值为0。函数在指向lpNumberOfBytesTransferred, lpCompletionKey, and lpOverlapped的参数指针中存储相关信息。调用GetLastError可以得到扩展错误信息 。

		// 第4种情况:
		// If a socket handle associated with a completion port is closed, GetQueuedCompletionStatus returns ERROR_SUCCESS, with lpNumberOfBytes equal zero. 
		// 如果关联到一个完成端口的一个socket句柄被关闭了，则GetQueuedCompletionStatus返回ERROR_SUCCESS（也是0）,并且lpNumberOfBytes等于0

		ULONG_PTR Key = 0;
		DWORD dwTransfer = 0;
		PER_IO_OPERATION_DATA *lpOverlapped = NULL;
		BOOL bStatus = GetQueuedCompletionStatus(
			m_hIocp,
			&dwTransfer,
			(PULONG_PTR)&Key,
			(LPOVERLAPPED *)&lpOverlapped,
			0/*INFINITE*/);
		if (dwTransfer == IOCP_OPERATION_EXIT) { //
			PRINTF("GetQueuedCompletionStatus Eixt\n");
			return;
		}
		int Pos = Key;
		// if(!bStatus) {
		//	PRINTF("GetQueuedCompletionStatus Error:%d \n", ::GetLastError());
		// 	if(NULL == lpOverlapped) {
		// 	 	//处理第2种情况
		// 		//continue;
		// 	}
		// 	DWORD dwErr = GetLastError();
		// 	if(Pos == 0) {
		// 		//continue;
		// 	} else {
		// 		//处理第3和第4种情况
		// 		if (WAIT_TIMEOUT == dwErr) {
		// 			//
		// 		} else {
		// 			//
		// 		}
		// 		//continue;
		// 	}
		// } 
		if (Pos > 0 && Pos <= uFD_SETSize) {
			std::unique_lock<std::mutex> lock(mutex_);
			std::shared_ptr<Socket> sock_ptr = sock_ptrs_[Pos - 1];
			lock.unlock();
			if (dwTransfer == IOCP_OPERATION_TRYRECEIVE) { //
				if(sock_ptr) {
					if (!sock_ptr->IsSelect(FD_READ)) {
						sock_ptr->Select(FD_READ);
					}
				}
				return;
			}
			if (dwTransfer == IOCP_OPERATION_TRYSEND) { //
				if(sock_ptr) {
					if (!sock_ptr->IsSelect(FD_WRITE)) {
						sock_ptr->Select(FD_WRITE);
					}
				}
				return;
			}
			if (dwTransfer == IOCP_OPERATION_TRYACCEPT) { //
				if(sock_ptr) {
					if (!sock_ptr->IsSelect(FD_ACCEPT)) {
						sock_ptr->Select(FD_ACCEPT);
					}
				}
				return;
			}
			if(!lpOverlapped) {
				if (sock_ptr) {
					sock_ptr->Trigger(FD_CLOSE, sock_ptr->GetLastError());
				}
				return;
			}
			if (!bStatus) {
				if (sock_ptr) {
					if (sock_ptr->IsListenSocket()) {
						int nErrorCode = sock_ptr->GetLastError();
						sock_ptr->Trigger(FD_ACCEPT, nErrorCode);
					} else if (sock_ptr->IsSelect(FD_CONNECT)) {
						sock_ptr->RemoveSelect(FD_CONNECT);
						int nErrorCode = sock_ptr->GetLastError();
						sock_ptr->Trigger(FD_CONNECT, nErrorCode);
					} else {
						int nErrorCode = sock_ptr->GetLastError();
						sock_ptr->Trigger(FD_CLOSE, nErrorCode);
					}
					if(lpOverlapped->OperationType == IOCP_OPERATION_ACCEPT) {
						if(lpOverlapped->Sock != INVALID_SOCKET) {
							XSocket::Socket::Close(lpOverlapped->Sock);
							lpOverlapped->Sock = INVALID_SOCKET;
						}
					}
				}
			} else {
				if (sock_ptr) {
					switch (lpOverlapped->OperationType)
					{	
					case IOCP_OPERATION_ACCEPT:
					{
						if(sock_ptr->IsSelect(FD_ACCEPT)) {
							// sock_ptr->SetSockOpt(
							// 	SOL_SOCKET
							// 	, SO_UPDATE_ACCEPT_CONTEXT
							// 	, (char*)&(lpOverlapped->Sock)
							// 	, sizeof(lpOverlapped->Sock));
							// SOCKADDR_IN *lpRemoteAddr = NULL, *lpLocalAddr = NULL;
							// int nRemoteAddrLen = sizeof(SOCKADDR_IN), nLocalAddrLen = sizeof(SOCKADDR_IN);
							// GetAcceptExSockaddrs(lpOverlapped->Buffer.buf, 0, 
							// 	sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, 
							// 	(LPSOCKADDR*)&lpLocalAddr, &nLocalAddrLen,
							// 	(LPSOCKADDR*)&lpRemoteAddr, &nRemoteAddrLen);
							//sprintf(pClientComKey->sIP, "%d", addrClient->sin_port );	//cliAdd.sin_port );
							sock_ptr->Trigger(FD_ACCEPT, nullptr, 0, (int)lpOverlapped->Sock);
						}
						if (sock_ptr->IsSocket()) {
							if (sock_ptr->IsSelect(FD_ACCEPT)) {
								sock_ptr->Trigger(FD_ACCEPT, 0);
							}
						}
					}
					break;
					case IOCP_OPERATION_CONNECT:
					{
						sock_ptr->SetSockOpt(
							SOL_SOCKET,
							SO_UPDATE_CONNECT_CONTEXT,
							NULL,
							0);
						if(sock_ptr->IsSelect(FD_CONNECT)) {
							sock_ptr->RemoveSelect(FD_CONNECT);
							sock_ptr->Trigger(FD_CONNECT, sock_ptr->GetLastError());
						}
					}
					break;
					case IOCP_OPERATION_RECEIVE:
					{
						lpOverlapped->NumberOfBytesReceived = dwTransfer;
						if (dwTransfer) {
							if (sock_ptr->IsSelect(FD_READ)) {
								sock_ptr->Trigger(FD_READ, lpOverlapped->Buffer.buf, lpOverlapped->NumberOfBytesReceived, 0);
							}
						if (sock_ptr->IsSocket()) {
							if (sock_ptr->IsSelect(FD_READ)) {
								sock_ptr->Trigger(FD_READ, 0);
							}
						}
						} else {
							PRINTF("GetQueuedCompletionStatus Recv Error:%d WSAError:%d\n", ::GetLastError(), sock_ptr->GetLastError());
							sock_ptr->Trigger(FD_CLOSE, sock_ptr->GetLastError());
						}
					}
					break;
					case IOCP_OPERATION_SEND:
					{
						lpOverlapped->NumberOfBytesSended = dwTransfer;
						if (dwTransfer) {
							if (sock_ptr->IsSelect(FD_WRITE)) {
								sock_ptr->Trigger(FD_WRITE, lpOverlapped->Buffer.buf, lpOverlapped->NumberOfBytesSended, 0);
							}
							if (sock_ptr->IsSocket()) {
								if (sock_ptr->IsSelect(FD_WRITE)) {
									sock_ptr->Trigger(FD_WRITE, 0);
								}
							}
						} else {
							PRINTF("GetQueuedCompletionStatus Send Error:%d WSAError:%d\n", ::GetLastError(), sock_ptr->GetLastError());
							sock_ptr->Trigger(FD_CLOSE, sock_ptr->GetLastError());
						}
					}
					break;
					default:
					{
						ASSERT(0);
					}
					break;
					}
				}
			}
		}
	}
};

}

#endif//_H_XIOCPSOCKETEX_H_
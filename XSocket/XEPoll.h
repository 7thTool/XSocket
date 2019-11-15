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

#ifndef _H_XEPOLL_H_
#define _H_XEPOLL_H_

#include "XSocketEx.h"
#include <sys/epoll.h>

namespace XSocket {

/*!
 *	@brief EPollSocket 模板定义.
 *
 *	封装EPollSocket
 */
template<class TSocketSet, class TBase = SocketEx>
class EPollSocket : public TBase
{
public:
	typedef TBase Base;
	typedef TSocketSet SocketSet;
public:
	inline SocketSet* ThisSocketSet() { return dynamic_cast<SocketSet*>(Service::service()); }

	EPollSocket():Base()
	{
		
	}

	virtual ~EPollSocket()
	{
		
	}

	int Send(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		int nSendLen = Base::Send(lpBuf, nBufLen, nFlags);
		if(nSendLen <= 0) {
			int nErrorCode = Base::GetLastError();
			switch(nErrorCode)
			{
			case 0:
				break;
			case EWOULDBLOCK:
			case EINTR:
				ThisSocketSet()->AsyncSelect(this, FD_WRITE);
				break;
			default:
				break;
			}	
		}
		return nSendLen;
	}

	int Receive(char* lpBuf, int nBufLen, int nFlags = 0)
	{
		int nRecvLen = Base::Receive(lpBuf, nBufLen, nFlags);
		if(nRecvLen <= 0) {
			int nErrorCode = Base::GetLastError();
			switch(nErrorCode)
			{
			case 0:
				break;
			case EWOULDBLOCK:
			case EINTR:
				ThisSocketSet()->AsyncSelect(this, FD_READ);
				break;
			default:
				break;
			}	
		}
		return nRecvLen;
	}
};

/*!
 *	@brief EPollSocketSet 模板定义.
 *
 *	封装EPollSocketSet，实现epoll模型
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class EPollSocketSet : public SocketSet<TService,TSocket,uFD_SETSize>
{
	typedef SocketSet<TService,TSocket,uFD_SETSize> Base;
protected:
	int m_epfd;
public:
	EPollSocketSet():m_epfd(0)
	{
		m_epfd = epoll_create(uFD_SETSize);
	}
	~EPollSocketSet() 
	{
		if (m_epfd) {
			close(m_epfd);
			m_epfd = 0;
		}
	}

	inline void AsyncSelect(SocketEx* sock_ptr, int evt) {
		sock_ptr->Select(evt);
		int fd = *sock_ptr;
		struct epoll_event event = {0};
		event.data.ptr = (void*)sock_ptr;
		event.events = 0 | EPOLLRDHUP
						| EPOLLPRI 
#ifdef USE_EPOLLET
						| EPOLLET
#endif//
		//				| EPOLLONESHOT
		;
		if (evt&FD_WRITE) {
			event.events |= EPOLLOUT;
		}
		if (evt&FD_READ) {
			event.events |= EPOLLIN;
		}
		epoll_ctl(m_epfd,EPOLL_CTL_MOD,fd,&event);
	}
	
	int AddSocket(TSocket* sock_ptr)
	{
		int i = Base::AddSocket(sock_ptr);
		if (i >= 0) {
			if (sock_ptr) {
				int fd = *sock_ptr;
				struct epoll_event event = {0};
				event.data.ptr = (void *)sock_ptr;
				//LT(默认)，LT+EPOLLONESHOT最可靠
				//ET，EPOLLET最高效,ET+EPOLLONESHOT高效可靠（这里使用）
				event.events = 0 
				| EPOLLIN //表示对应的文件描述符可以读（包括对端SOCKET正常关闭）；
				| EPOLLOUT //表示对应的文件描述符可以写；
				| EPOLLRDHUP //Stream socket peer closed connection, or shut down writing  half of connection.
				| EPOLLPRI //表示对应的文件描述符有紧急的数据可读（这里应该表示有带外数据到来）；
				//| EPOLLERR //表示对应的文件描述符发生错误；不用注册，会自动触发
				//| EPOLLHUP //表示对应的文件描述符被挂断；不用注册，会自动触发
#ifdef USE_EPOLLET
				| EPOLLET //将EPOLL设为边缘触发(Edge Triggered)模式，这是相对于水平触发(LevelTriggered)来说的；
#endif
				//| EPOLLONESHOT //只监听一次事件，当监听完这次事件之后，如果还需要继续监听这个socket的话，需要再次把这个socket加入到EPOLL队列里
				;
				if (SOCKET_ERROR != epoll_ctl(m_epfd, EPOLL_CTL_ADD, fd, &event)) {
					return i;
				} else {
					PRINTF("epoll_ctl err:%d\n", XSocket::GetLastError());
				}
			} else {
				//测试可不可以增加Socket，返回true表示可以增加
				return i;
			}
		}
		return -1;
	}

	int RemoveSocket(TSocket* sock_ptr)
	{
		int i = Base::RemoveSocket(sock_ptr);
		if (i >= 0) {
			if (sock_ptr) {
				if (sock_ptr->IsSocket()) {
					int fd = *sock_ptr;
					struct epoll_event event = {0};
					event.data.ptr = (void *)sock_ptr;
					epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, &event);
				} 
				return i;
			} else {
				return i;
			}
		}
		return -1;
	}

	void RemoveAllSocket(bool bClose = false)
	{
		std::unique_lock<std::mutex> lock(Base::mutex_);
		int i;
		for (i = 0; i < uFD_SETSize; i++)
		{
			if (Base::sock_ptrs_[i]) {
				TSocket* sock_ptr = Base::sock_ptrs_[i];
				if (sock_ptr->IsSocket()) {
					int fd = *sock_ptr;
					struct epoll_event event = {0};
					event.data.ptr = (void*)sock_ptr;
					epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, &event);
					if (bClose) {
						sock_ptr->Close();
					}
				}
				Base::sock_ptrs_[i] = NULL;
			}
		}
		Base::sock_count_ = 0;
	}

protected:

	virtual void OnRunOnce()
	{
		Base::OnRunOnce();

		int i;
		int nfds = 0;
		struct epoll_event events[uFD_SETSize] = {0};
		//Specifying a timeout of -1 makes epoll_wait wait indefinitely, while specifying a timeout equal to zero makes epoll_wait to return immediately even if no events are available (return code equal to zero).
		nfds = epoll_wait(m_epfd, events, uFD_SETSize, -1);
		if (nfds > 0) {
			for (i = 0; i < nfds; ++i)
			{
				struct epoll_event event = events[i];
				TSocket *sock_ptr = (TSocket *)event.data.ptr;
				unsigned int evt = event.events;
				ASSERT(sock_ptr);
				int fd = *sock_ptr;
				int nErrorCode = 0;
				//参考NGIX逻辑...
				//if(evt&(EPOLLRDHUP|EPOLLERR|EPOLLHUP)) {
				//	PRINTF("epoll_wait error: fd=%d event=%04XD\n" , fd, evt);
				//}
				//if ((evt&(EPOLLRDHUP|EPOLLERR|EPOLLHUP)) && (evt&(EPOLLIN|EPOLLOUT))==0) {
				//	/*
				//	 * if the error events were returned without EPOLLIN or EPOLLOUT,
				//	 * then add these flags to handle the events at least in one
				//	 * active handler
				//	 */
				//	evt |= EPOLLIN|EPOLLOUT;
				//}
				if (sock_ptr->IsSocket() && evt & EPOLLPRI) {
					//有紧急数据
					if (sock_ptr->IsSelect(FD_OOB)) {
						sock_ptr->Trigger(FD_OOB, 0);
					}
				}
				if (sock_ptr->IsSocket() && evt & EPOLLIN) {
					//有新的可读数据
					if (sock_ptr->IsSelect(FD_ACCEPT)) {
						sock_ptr->Trigger(FD_ACCEPT, 0);
					} else {
						if (sock_ptr->IsSelect(FD_READ)) {
							sock_ptr->Trigger(FD_READ, 0);
						}
					}
				}
				if (sock_ptr->IsSocket() && evt & EPOLLOUT) {
					//有新的可写数据
					if (sock_ptr->IsSelect(FD_CONNECT)) {
						if (nErrorCode == 0) {
							int nOptLen = sizeof(nErrorCode);
							sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, (void *)&nErrorCode, nOptLen);
						}
						sock_ptr->Trigger(FD_CONNECT, nErrorCode);
						sock_ptr->RemoveSelect(FD_CONNECT);
					} 
					if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_WRITE)) {
						sock_ptr->Trigger(FD_WRITE, 0);
					}
					if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_READ)) {
						sock_ptr->Trigger(FD_READ, 0);
					}
				}
// #ifndef USE_EPOLLET
// 				if (sock_ptr->IsSocket()) {
// 					event.data.ptr = (void *)sock_ptr;
// 					event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT;
// 					epoll_ctl(m_epfd, EPOLL_CTL_MOD, fd, &event);
// 				}
// #endif //
			}
		} else {
			//
		}
	}
};

/*!
 *	@brief EPollServer 模板定义.
 *
 *	封装EPollServer，实现对epoll模型管理监听Socket连接，依赖EPollManager
 */
template<class T, class TService, class TBase, class TSocketSet>
class EPollServer 
: public SelectListen<T,TService,TBase,typename TSocketSet::Socket>
, public SocketManager<TSocketSet>
{
public:
	typedef typename SocketSet::Socket Socket;
	typedef TSocketSet SocketSet;
	typedef SocketManager<SocketSet> SockManager;
	typedef SelectListen<T,TService,TBase,Socket> Base;
public:
	EPollServer(int nMaxSocketCount) : Base(),SockManager((nMaxSocketCount+SocketSet::GetMaxSocketCount()-1)/SocketSet::GetMaxSocketCount())
	{
		
	}

	~EPollServer()
	{
		Base::Stop();
	}
};

}

#endif//_H_XEPOLL_H_
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
#include <sys/eventfd.h>

namespace XSocket {

/*!
 *	@brief EPollSocket 模板定义.
 *
 *	封装EPollSocket
 */
template<class TSocketSet, class TBase = SocketEx, class TSockAddr = SOCKADDR_IN>
class EPollSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef TSocketSet SocketSet;
	typedef TSockAddr SockAddr;
public:
	static SocketSet* service() { return dynamic_cast<SocketSet*>(SocketSet::service()); }

	EPollSocketT():Base()
	{
		
	}

	virtual ~EPollSocketT()
	{
		
	}
	
	inline void Select(int lEvent) {  
		int lAsyncEvent = 0;
		if(!Base::IsSelect(FD_READ) && (lEvent & FD_READ)) {
			lAsyncEvent |= FD_READ;
		}
		if(!Base::IsSelect(FD_WRITE) && (lEvent & FD_WRITE)) {
			lAsyncEvent |= FD_WRITE;
		}
		if(!Base::IsSelect(FD_ACCEPT) && (lEvent & FD_ACCEPT)) {
			lAsyncEvent |= FD_ACCEPT;
		}
		if(!Base::IsSelect(FD_IDLE) && (lEvent & FD_IDLE)) {
			lAsyncEvent |= FD_IDLE;
		}
		Base::Select(lEvent);
		if(lAsyncEvent) {
			service()->SelectSocket(this,lAsyncEvent);
		}
		if(lAsyncEvent & FD_READ) {
			Base::Trigger(FD_READ, 0);
		}
		if(lAsyncEvent & FD_WRITE) {
			Base::Trigger(FD_WRITE, 0);
		}
		if(lAsyncEvent & FD_ACCEPT) {
			Base::Trigger(FD_ACCEPT, 0);
		}
	}
};

/*!
 *	@brief EPollServiceT 模板定义.
 *
 *	封装EPollServiceT，实现epoll模型
 */
template<class TService = Service>
class EPollServiceT : public TService
{
	typedef TService Base;
protected:
	int epfd_ = 0;
	int evfd_ = 0;
	int evfd_pair_[2] = {0};
public:
	EPollServiceT()
	{
		epfd_ = epoll_create(1024); //大于0即可，保险方式设置1024足够了
		if(epfd_) {
			evfd_ = eventfd(0, EFD_NONBLOCK);
			if(!evfd_) {
        		PRINTF("create event fd failed, errno(%d): %s\n", errno, strerror(errno));
			} else {
				struct epoll_event event = {0};
				event.data.ptr = nullptr;
				event.data.fd = evfd_;
				event.events = EPOLLIN | EPOLLERR;
				epoll_ctl(epfd_, EPOLL_CTL_ADD, evfd_, &event);
			}
			//if(socketpair(AF_UNIX, SOCK_STREAM, 0, evfd_pair_) == -1) { //OK
			if(pipe(evfd_pair_) == -1) { //OK
			//if(Socket::CreatePair(AF_UNIX, SOCK_STREAM, 0, evfd_pair_) == -1) { //OK
        		PRINTF("create fd pair failed, errno(%d): %s\n", errno, strerror(errno));
    		} else {
				struct epoll_event event = {0};
				event.data.ptr = nullptr;
				event.data.fd = evfd_pair_[0];
				event.events = EPOLLIN | EPOLLERR;
				epoll_ctl(epfd_, EPOLL_CTL_ADD, evfd_pair_[0], &event);
			}
		}
	}
	~EPollServiceT() 
	{
		if (epfd_) {
			if(evfd_pair_[0]) {
				epoll_ctl(epfd_, EPOLL_CTL_DEL, evfd_pair_[0], nullptr);
				close(evfd_pair_[0]);
				close(evfd_pair_[1]);
				evfd_pair_[0] = 0;
				evfd_pair_[1] = 0;
			}
			if(evfd_) {
				epoll_ctl(epfd_, EPOLL_CTL_DEL, evfd_, nullptr);
				close(evfd_);
				evfd_ = 0;
			}
			close(epfd_);
			epfd_ = 0;
		}
	}
	
	inline void PostNotify()
	{
		Base::PostNotify();
		const size_t data = 1;
		write(evfd_, &data, sizeof(data));
	}

	inline void PostNotify(void* data)
	{
		write(evfd_pair_[1], &data, sizeof(data));
	}

protected:
	//
	virtual void OnNotify(void* data)
	{
		//PRINTF("OnNotify %p", data);
	}

	virtual void OnEPollEvent(const epoll_event& event)
	{
		//
	}
	
	virtual void OnRunOnce()
	{
		Base::OnRunOnce();

		struct epoll_event events[1024] = {0};
		//Specifying a timeout of -1 makes epoll_wait wait indefinitely, while specifying a timeout equal to zero makes epoll_wait to return immediately even if no events are available (return code equal to zero).
		int nfds = epoll_wait(epfd_, events, 1024, Base::GetWaitingTimeOut());
		if (nfds > 0) {
			for (int i = 0; i < nfds; ++i)
			{
				const struct epoll_event& event = events[i];
				if(evfd_ == event.data.fd) {
					size_t data = 0;
					if(sizeof(size_t) == read(event.data.fd, &data, sizeof(data))) {
						//PRINTF("OnNotify %u", data);
					}
				} else if(evfd_pair_[0] == event.data.fd) {
					void* data = 0;
					if(sizeof(void*) == read(event.data.fd, &data, sizeof(data))) {
						OnNotify(data);
					}
				} else {
					OnEPollEvent(event);
				}
			}
		} else {
			//
		}
	}
};

typedef ThreadServiceT<EPollServiceT<Service>> EPollService;

/*!
 *	@brief EPollSocketSet 模板定义.
 *
 *	封装EPollSocketSet，实现epoll模型
 */
template<class TService = EPollService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class EPollSocketSetT : public SocketSetT<TService,TSocket,uFD_SETSize>
{
	typedef SocketSetT<TService,TSocket,uFD_SETSize> Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
public:
	EPollSocketSetT()
	{
	}
	~EPollSocketSetT() 
	{
	}

	void SelectSocket(SocketEx* sock_ptr, int evt) {
		//Base::SelectSocket(sock_ptr, evt);
		int fd = *sock_ptr;
		struct epoll_event event = {0};
		event.data.ptr = (void*)sock_ptr;
		event.events = 0 
		| EPOLLRDHUP
						
#ifdef USE_EPOLLET
		| EPOLLET
#endif//
		//| EPOLLONESHOT
		;
		if (sock_ptr->IsSelect(FD_READ|FD_ACCEPT)) {
			event.events |= EPOLLIN;
		}
		if (sock_ptr->IsSelect(FD_OOB)) {
			event.events |= EPOLLPRI;
		}
		if (sock_ptr->IsSelect(FD_WRITE|FD_CONNECT)) {
			event.events |= EPOLLOUT;
		}
		epoll_ctl(Base::epfd_,EPOLL_CTL_MOD,fd,&event);
	}
	
	int AddSocket(std::shared_ptr<Socket> sock_ptr, int evt = 0)
	{
		std::unique_lock<std::mutex> lock(Base::mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(Base::sock_ptrs_[i]==NULL) {
				if (sock_ptr) {
					Base::sock_count_++;
					Base::sock_ptrs_[i] = sock_ptr;
					sock_ptr->AttachService(this);
					sock_ptr->SocketEx::Select(evt);
					int fd = *sock_ptr;
					struct epoll_event event = {0};
					event.data.ptr = (void *)sock_ptr.get();
					//LT(默认)，LT+EPOLLONESHOT最可靠
					//ET，EPOLLET最高效,ET+EPOLLONESHOT高效可靠
					event.events = 0 
					//| EPOLLIN //表示对应的文件描述符可以读（包括对端SOCKET正常关闭）；
					//| EPOLLPRI //表示对应的文件描述符有紧急的数据可读（这里应该表示有带外数据到来）；
					//| EPOLLOUT //表示对应的文件描述符可以写；
					| EPOLLRDHUP //Stream socket peer closed connection, or shut down writing  half of connection.
					//| EPOLLERR //表示对应的文件描述符发生错误；不用注册，会自动触发
					//| EPOLLHUP //表示对应的文件描述符被挂断；不用注册，会自动触发
	#ifdef USE_EPOLLET
					| EPOLLET //将EPOLL设为边缘触发(Edge Triggered)模式，这是相对于水平触发(LevelTriggered)来说的；
	#endif
					//| EPOLLONESHOT //只监听一次事件，当监听完这次事件之后，如果还需要继续监听这个socket的话，需要再次把这个socket加入到EPOLL队列里
					;
					if (sock_ptr->IsSelect(FD_READ|FD_ACCEPT)) {
						event.events |= EPOLLIN;
					}
					if (sock_ptr->IsSelect(FD_OOB)) {
						event.events |= EPOLLPRI;
					}
					if (sock_ptr->IsSelect(FD_WRITE|FD_CONNECT)) {
						event.events |= EPOLLOUT;
					}
					if (SOCKET_ERROR != epoll_ctl(Base::epfd_, EPOLL_CTL_ADD, fd, &event)) {
						//return i;
					} else {
						PRINTF("epoll_ctl err:%d", XSocket::Socket::GetLastError());
					}
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
	inline int AddConnect(std::shared_ptr<Socket> sock_ptr, u_short port)
	{
		if(sock_ptr) {
			sock_ptr->Connect(port);
		}
		return AddSocket(sock_ptr);
	}
	inline int AddAccept(std::shared_ptr<Socket> sock_ptr)
	{
		return AddSocket(sock_ptr,FD_ACCEPT);
	}

	int RemoveSocket(std::shared_ptr<Socket> sock_ptr)
	{
		//std::unique_lock<std::mutex> lock(Base::mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(Base::sock_ptrs_[i]==sock_ptr) {
				int fd = *sock_ptr;
				struct epoll_event event = {0};
				event.data.ptr = (void *)sock_ptr.get();
				epoll_ctl(Base::epfd_, EPOLL_CTL_DEL, fd, &event);
				return Base::RemoveSocketByPos(i);
			}
		}
		return -1;
	}

protected:
	//
	virtual void OnEPollEvent(const epoll_event& event)
	{
		std::unique_lock<std::mutex> lock(Base::mutex_);
		std::shared_ptr<Socket> sock_ptr = Base::FindSocket((Socket *)event.data.ptr);
		lock.unlock();
		if (!sock_ptr) {
			return;
		}
		unsigned int evt = event.events;
		int fd = *sock_ptr;
		int nErrorCode = 0;
#ifdef _DEBUG
		if (evt & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
			PRINTF("epoll_wait error: fd=%d event=%u", fd, evt);
		}
#endif
		if ((evt & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) && (evt & (EPOLLIN | EPOLLOUT)) == 0) {
			/*
			 * if the error events were returned without EPOLLIN or EPOLLOUT,
			 * then add these flags to handle the events at least in one
			 * active handler
			 */
			if (sock_ptr->IsSelect(FD_READ|FD_ACCEPT)) {
				evt |= EPOLLIN;
			}
			if (sock_ptr->IsSelect(FD_WRITE|FD_CONNECT)) {
				evt |=  EPOLLOUT;
			}
		}
		if (sock_ptr->IsSocket() && (evt & EPOLLPRI)) {
			//有紧急数据
			if (sock_ptr->IsSelect(FD_OOB)) {
				sock_ptr->Trigger(FD_OOB, 0);
			}
		}
		if (sock_ptr->IsSocket() && (evt & EPOLLIN)) {
			//有新的可读数据
			if (sock_ptr->IsSelect(FD_ACCEPT)) {
				sock_ptr->Trigger(FD_ACCEPT, 0);
			} else {
				if (sock_ptr->IsSelect(FD_READ)) {
					sock_ptr->Trigger(FD_READ, 0);
				}
			}
		}
		if (sock_ptr->IsSocket() && (evt & EPOLLOUT)) {
			//有新的可写数据
			if (sock_ptr->IsSelect(FD_CONNECT)) {
				sock_ptr->RemoveSelect(FD_CONNECT);
				if (nErrorCode == 0) {
					sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, (void *)&nErrorCode, sizeof(nErrorCode));
				}
				sock_ptr->Trigger(FD_CONNECT, nErrorCode);
			} else if (sock_ptr->IsSelect(FD_WRITE)) {
				sock_ptr->Trigger(FD_WRITE, 0);
			}
		}
// #ifndef USE_EPOLLET
// 		if (sock_ptr->IsSocket()) {
// 			event.data.ptr = (void *)sock_ptr;
// 			event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT;
// 			epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &event);
// 		}
// #endif //
	}
};

}

#endif//_H_XEPOLL_H_
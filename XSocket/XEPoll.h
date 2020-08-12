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
#ifndef _H_XEPOLL_H_
#define _H_XEPOLL_H_

#include "XSocketEx.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

namespace XSocket {

/*!
 *	@brief EPollSocket 模板定义.
 *
 *	封装EPollSocket
 */
template<class TSocketSet, class TBase = SocketEx>
class EPollSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef TSocketSet SocketSet;
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
	int timerfd_ = -1;
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
			timerfd_ = timerfd_create(CLOCK_REALTIME, O_NONBLOCK);
			if(timerfd_ == -1) {
				PRINTF("timerfd_create failed, errno(%d): %s\n", errno, strerror(errno));
			} else {
				struct epoll_event event = {0};
				event.data.ptr = nullptr;
				event.data.fd = timerfd_;
				event.events = EPOLLIN | EPOLLERR | EPOLLET;
				epoll_ctl(epfd_, EPOLL_CTL_ADD, timerfd_, &event);
			}
		}
	}
	~EPollServiceT() 
	{
		if (epfd_) {
			if(timerfd_) {
				epoll_ctl(epfd_, EPOLL_CTL_DEL, timerfd_, nullptr);
				close(timerfd_);
				timerfd_ = 0;
			}
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

	inline void PostTimer(size_t millis)
	{
		//使用timerfd实现定时器
		//Base::PostTimer(millis);
		if(timerfd_ == -1) {
			return;
		} 
		// The it_value field returns the amount of time until the timer will
       	// next expire.  If both fields of this structure are zero, then the
       	// timer is currently disarmed.
		struct itimerspec curr_value = {0};
		timerfd_gettime(timerfd_, &curr_value);
		if(curr_value.it_value.tv_sec || curr_value.it_value.tv_nsec) {
			if((curr_value.it_value.tv_sec *1000 + curr_value.it_value.tv_nsec/1000/1000) < millis) {
				//说明有更快的定时器任务需要执行
				return;
			}
		}

		struct timespec now;
		if (clock_gettime(CLOCK_REALTIME, &now) == -1)
			return;
		struct itimerspec new_value = {0};
		millis += now.tv_nsec/1000/1000;
		new_value.it_value.tv_sec = now.tv_sec + millis/1000;
		new_value.it_value.tv_nsec = millis%1000*1000*1000;
		timerfd_settime(timerfd_, TFD_TIMER_ABSTIME, &new_value, NULL);
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
	
	virtual void OnWait()
	{
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
				} else if(timerfd_ == event.data.fd) {
					uint64_t data = 0;
					if(sizeof(uint64_t) == read(event.data.fd, &data, sizeof(data))) {
						//PRINTF("OnTimer %u", data);
						OnTimer();
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
template<class TService = EPollService, class TSocket = SocketEx>
class EPollSocketSetT : public SocketSetT<TService,TSocket>
{
	typedef SocketSetT<TService,TSocket> Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
public:
	EPollSocketSetT(int nMaxSocketCount):Base(nMaxSocketCount)
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
						
#if USE_EPOLLET
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
		int i, j = sock_ptrs_.size();
		for (i = 0; i < j; i++)
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
	#if USE_EPOLLET
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
	template<class Ty = Socket>
	inline int AddConnect(std::shared_ptr<Ty> sock_ptr, u_short port)
	{
		if(sock_ptr) {
			sock_ptr->Connect(port);
		}
		return AddSocket(std::static_pointer_cast<Socket>(sock_ptr));
	}
	inline int AddAccept(std::shared_ptr<Socket> sock_ptr)
	{
		return AddSocket(sock_ptr,FD_ACCEPT);
	}

	int RemoveSocket(std::shared_ptr<Socket> sock_ptr)
	{
		//std::unique_lock<std::mutex> lock(Base::mutex_);
		int i, j = sock_ptrs_.size();
		for (i = 0; i < j; i++)
		{
			if(Base::sock_ptrs_[i]==sock_ptr) {
				if (sock_ptr->IsSocket()) {
					int fd = *sock_ptr;
					struct epoll_event event = {0};
					event.data.ptr = (void *)sock_ptr.get();
					epoll_ctl(Base::epfd_, EPOLL_CTL_DEL, fd, &event);
				}
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
// #if USE_EPOLLET
// #else
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
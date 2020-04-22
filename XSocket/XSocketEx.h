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
#ifndef _H_XSOCKETEX_H_
#define _H_XSOCKETEX_H_

#include <atomic>
#include <mutex>
#ifndef WIN32
#include <condition_variable>
#endif
#include <thread>
#include <future>
#include <functional>
#include <algorithm>
#include <vector>
#include <queue>
#include <set>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "XSocket.h"

namespace XSocket {

	class SocketEx;
	class Service;

/*!
 *	@brief Socket 角色定义.
 *
 *	定义Socket在网络中扮演的角色
 */
enum
{
	SOCKET_ROLE_NONE = 0,		//!< 未知
	SOCKET_ROLE_LISTEN,			//!< Server端监听Socket	
	SOCKET_ROLE_WORK,			//!< Server端Accept到的Socket或者UDP套接字
	SOCKET_ROLE_CONNECT,		//!< Client端连接Socket
};


/*!
 *	@brief Socket 标志定义.
 *
 *	给Socket增加标志位，一遍跟踪特定标志的Socket
 */
enum
{
	SOCKET_FLAG_DEBUG = 0x01, //调试标志，如果设置会额外输出该Socket的调试信息
	SOCKET_FLAG_USER1 = 0x02, //用户自定义标志1
	SOCKET_ROLE_USER2 = 0x04, //用户自定义标志2
	SOCKET_ROLE_USER3 = 0x08, //用户自定义标志3
	SOCKET_ROLE_USER4 = 0x10, //用户自定义标志4
};


/*!
 *	@brief 可伸缩的Socket封装.
 *
 *	SocketEx定义了可伸缩Socket的接口和基本实现
 */
class XSOCKET_API SocketEx : public Socket
{
	typedef Socket Base;
public:
	static std::future<struct addrinfo*> AsyncGetAddrInfo( const char *hostname, const char *service, const struct addrinfo *hints);
public:
	SocketEx();
	virtual ~SocketEx();

	//只需重载Attach，因为Open和Detach都会调用Attach
	SOCKET Open(int nSockAf = AF_INET, int nSockType = SOCK_STREAM, int nSockProtocol = 0);
	SOCKET Attach(SOCKET Sock, int Role = SOCKET_ROLE_NONE);
	SOCKET Detach();

	int ShutDown(int nHow = Both);
	int Close();

	int Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen);
	int Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen);
	int Listen(int nConnectionBacklog = 5);
	// SOCKET Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen);

	// int Send(const char* lpBuf, int nBufLen, int nFlags = 0);
	// int Receive(char* lpBuf, int nBufLen, int nFlags = 0);
	// int SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags = 0);
	// int ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags = 0);

	inline int Role() { return role_; }
	inline bool IsNoneRole() { return	Role()==SOCKET_ROLE_NONE; }
	inline bool IsConnectSocket() { return Role()==SOCKET_ROLE_CONNECT; }
	inline bool IsListenSocket() { return Role()==SOCKET_ROLE_LISTEN; }
	inline bool IsWorkSocket() { return Role()==SOCKET_ROLE_WORK; }

	inline void SetFlags(int flags) { flags_ = flags; }
	inline int Flags() { return flags_; }
	inline bool IsDebug() { return flags_ & SOCKET_FLAG_DEBUG; }

	inline void AttachService(Service* svr) { OnAttachService(svr); }
	inline void DetachService(Service* svr) { OnDetachService(svr); }
	
	inline void Select(int lEvent) { event_ |= lEvent; }
	inline void RemoveSelect(int lEvent) { event_ &= ~lEvent; }
	inline bool IsSelect(int evt, bool all = false) {
		if(all) {
			return event_ & evt == evt;
		} 
		return event_ & evt;
	}
	inline bool IsSelectRead() { return IsSelect(FD_READ|FD_OOB|FD_ACCEPT); }
	inline bool IsSelectWrite() { return IsSelect(FD_WRITE|FD_CONNECT); }

	inline void Trigger(int evt, int nErrorCode) {
		if(evt == FD_IDLE) {
			OnIdle();
		}
		if(!IsSocket()) { 
			return;
		}
		switch (evt)
		{
		case FD_READ:
			OnReceive(nErrorCode);
			break;
		case FD_WRITE:
			OnSend(nErrorCode);
			break;
		case FD_OOB:
			OnOOB(nErrorCode);
			break;
		case FD_ACCEPT:
			OnAccept(nErrorCode);
			break;
		case FD_CONNECT:
			OnConnect(nErrorCode);
			break;
		case FD_CLOSE:
			OnClose(nErrorCode);
			break;
		// case FD_IDLE:
		// 	OnIdle();
		// 	break;
		default:
			break;
		}
	}
	
	inline void Trigger(int evt, const char* lpBuf, int nBufLen, int nFlags) { 
		if(!IsSocket()) { 
			return;
		}
		switch (evt)
		{
		case FD_READ:
			OnReceive(lpBuf, nBufLen, nFlags);
			break;
		case FD_WRITE:
			OnSend(lpBuf, nBufLen, nFlags);
			break;
		case FD_OOB:
			OnOOB(lpBuf, nBufLen, nFlags);
			break;
		case FD_ACCEPT:
			break;
		case FD_CONNECT:
			break;
		case FD_CLOSE:
			break;
		case FD_IDLE:
			break;
		default:
			break;
		}
	}

	inline void Trigger(int evt, SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen) { 
		if(!IsSocket()) { 
			return;
		}
		switch (evt)
		{
		case FD_ACCEPT:
			OnAccept(Sock, lpSockAddr, nSockAddrLen);
			break;
		case FD_CONNECT:
			break;
		case FD_CLOSE:
			break;
		case FD_IDLE:
			break;
		default:
			break;
		}
	}

	inline void Trigger(int evt, const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags) { 
		if(!IsSocket()) { 
			return;
		}
		switch (evt)
		{
		case FD_READ:
			OnReceiveFrom(lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags);
			break;
		case FD_WRITE:
			OnSendTo(lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags);
			break;
		case FD_OOB:
			break;
		case FD_ACCEPT:
			break;
		case FD_CONNECT:
			break;
		case FD_CLOSE:
			break;
		case FD_IDLE:
			break;
		default:
			break;
		}
	}

protected:
	/*!
	 *	@brief 通知套接字扮演指定角色.
	 *
	 *	收到这个回调，说明Socket完成了初始化了，并开始进入指定角色
	 *	@param nRole indicates this socket to play as a role (listen / accept/ connect)
	 *	SOCKET_ROLE_NONE
	 *	SOCKET_ROLE_LISTEN
	 *	SOCKET_ROLE_WORK
	 *	SOCKET_ROLE_CONNECT
	 *	other value indecate unknown error.
	 */
	virtual void OnRole(int nRole);

	/*!
	 *	@brief 通知套接字绑定/解除绑定服务对象.
	 *
	 *	收到这个回调，说明Socket加入/离开了服务管理，接下来开始进入/退出Select事件通知处理了
	 *	@param pSvr 服务对象指针
	 */
	virtual void OnAttachService(Service* pSvr);
	virtual void OnDetachService(Service* pSvr);

	/*!
	 *	@brief 通知套接字无可操作状态，正在空闲或者等待中.
	 *
	 *	OnIdle函数是后台在计算空闲的情况，给SocketEx用于做一些空闲处理动作，比如检查超时
	 *	、清理垃圾数据等等
	 */
	virtual void OnIdle();

	/*!
	 *	@brief 通知套接字有数据可以通过调用Receive读取.
	 *
	 *	
	 *	Notifies a this socket that there is data to be retrieved by calling Receive.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes apply to the OnReceive member function:
	 *	0					The function executed successfully.
	 *	ENETDOWN			The Windows Sockets implementation detected that the network subsystem failed.
	 */
	virtual void OnReceive(int nErrorCode);
	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags);
	virtual void OnReceiveFrom(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags);
	
	/*!
	 *	@brief 通知套接字可以调用Send发送数据.
	 *
	 *	
	 *	Notifies a socket that it can send data by calling Send.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes apply to the OnSend member function:
	 *	0					The function executed successfully.
	 *	ENETDOWN			The Windows Sockets implementation detected that the network subsystem failed.
	 */
	virtual void OnSend(int nErrorCode);
	virtual void OnSend(const char* lpBuf, int nBufLen, int nFlags);
	virtual void OnSendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags);
	
	/*!
	 *	@brief 通知正在接收数据的套接字有带外数据，通常是紧急数据 要读取.
	 *
	 *	
	 *	Notifies a receiving socket that there is out-of-band data to be read on the socket, usually an urgent message.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes apply to the OnOutOfBandData member function:
	 *	0					The function executed successfully.
	 *	ENETDOWN			The Windows Sockets implementation detected that the network subsystem failed.
	 */
	virtual void OnOOB(int nErrorCode);
	virtual void OnOOB(const char* lpBuf, int nBufLen, int nFlags);

	/*!
	 *	@brief 通知正在监听的服务器套接字有一个连接需要调用Accept接收连接.
	 *
	 *	
	 *	Notifies a listening socket that it can accept pending connection requests by calling Accept.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes applies to the OnAccept member function:
	 *	0					The function executed successfully.
	 *	ENETDOWN			The Windows Sockets implementation detected that the network subsystem failed.
	 */
	virtual void OnAccept(int nErrorCode);
	virtual void OnAccept(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen);

	/*!
	 *	@brief 通知正在连接的客户端套接字连接建立完成，可能成功或者失败.
	 *
	 *	
	 *	Notifies a connecting socket that the connection attempt is complete, whether successfully or in error.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes apply to the OnConnect member function:
	 *	0					The function executed successfully.
	 *	WSAEADDRINUSE		The specified address is already in use.
	 *	WSAEADDRNOTAVAIL	The specified address is not available from the local machine.
	 *	WSAEAFNOSUPPORT		Addresses in the specified family cannot be used with this socket.
	 *	WSAECONNREFUSED		The attempt to connect was forcefully rejected.
	 *	WSAEDESTADDRREQ		A destination address is required.
	 *	WSAEFAULT			The lpSockAddrLen argument is incorrect.
	 *	WSAEINVAL			The socket is already bound to an address.
	 *	WSAEISCONN			The socket is already connected.
	 *	WSAEMFILE			No more file descriptors are available.
	 *	WSAENETUNREACH		The network cannot be reached from this host at this time.
	 *	WSAENOBUFS			No buffer space is available. The socket cannot be connected.
	 *	WSAENOTCONN			The socket is not connected.
	 *	WSAENOTSOCK			The descriptor is a file, not a socket.
	 *	WSAETIMEDOUT		The attempt to connect timed out without establishing a connection.
	 */
	virtual void OnConnect(int nErrorCode);

	/*!
	 *	@brief 通知套接字连接已经关闭.
	 *
	 *	
	 *	Notifies a socket that the socket connected to it has closed.
	 *	@param nErrorCode The most recent error on a socket. 
	 *	The following error codes apply to the OnClose member function:
	 *	0					The function executed successfully.
	 *	ENETDOWN			The Windows Sockets implementation detected that the network subsystem failed.
	 *	WSAECONNRESET		The connection was reset by the remote side.
	 *	WSAECONNABORTED		The connection was aborted due to timeout or other failure.
	 */
	virtual void OnClose(int nErrorCode);

protected:
	uint8_t role_:3;
	uint8_t flags_:5;
	uint8_t event_;

private:
	SocketEx(const SocketEx& Sock) {};
	void operator=(const SocketEx& Sock) {};
};

/*!
 *	@brief SocketExT 模板定义.
 *
 *	封装SocketEx，一般用于SocketEx最终实现的包装
 */
template<class TBase = SocketEx>
class SocketExT : public TBase
{
	typedef TBase Base;
protected:
	//
	virtual void OnClose(int nErrorCode)
	{
		Base::OnClose(nErrorCode);
		Base::Close();
	}
};

/*!
 *	@brief SocketExImpl 模板定义.
 *
 *	封装SocketEx，一般用于SocketEx最终实现的包装
 */
template<class T, class TBase = SocketEx>
class SocketExImpl : public TBase
{
	typedef TBase Base;
public:
	SocketExImpl():Base()
	{

	}

protected:
	//
	virtual void OnClose(int nErrorCode)
	{
		T* pT = static_cast<T*>(this);

		Base::OnClose(nErrorCode);

		pT->Close();
	}
};

/*!
 *	@brief Service 定义.
 *
 *	封装Service，实现基本服务框架
 */
class Service 
{
protected:
    //停止标记，默认停止状态，启动后停止状态为false
    std::atomic<bool> stop_flag_;
	uint32_t idle_flag_:1; //空闲处理标志,0表示不执行空闲任务，1表示执行空闲任务
	uint32_t notify_flag_:1; //通知处理标志,0表示没有通知任务，1表示有通知任务
	uint32_t wait_timeout_:30; //服务等待时间（毫秒）
	std::chrono::steady_clock::time_point timer_time_; //最短定时任务时间,0表示没有定时任务，非0表示最短定时任务
public:
	static Service* service();

	Service();

	inline bool StartTest()
	{
		bool expected = true;
		if (!stop_flag_.compare_exchange_strong(expected, false)) {
			return false; //已经Start过了
		}
		return true;
	}
	inline void Start() { ASSERT(!IsStopFlag()); }
	inline bool StopTest()
	{
		bool expected = false;
		if (!stop_flag_.compare_exchange_strong(expected, true)) {
			return false; //已经Stop过了
		}
		return true;
	}
	inline void Stop() { ASSERT(IsStopFlag()); }
	inline bool IsStopFlag() { return stop_flag_; }

	inline void SetWaitTimeOut(size_t millis) { wait_timeout_ = millis; }
	inline size_t GetWaitTimeOut() { return wait_timeout_; }
	
	inline void PostNotify() { notify_flag_ = true; idle_flag_ = false; }
	inline void PostTimer(size_t millis) { 
		std::chrono::steady_clock::time_point time = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
		if(!timer_time_.time_since_epoch().count()) {
			timer_time_ = time;
		} else if(timer_time_ > time) { 
			timer_time_ = time; 
		} 
	}
	
	//inline void SelectSocket(SocketEx* sock_ptr, int evt) {}

	inline void RemoveSocket(SocketEx* sock_ptr) {}

protected:
	//
	inline size_t GetWaitingTimeOut()
	{
		if(notify_flag_) {
			return 0;
		}
		if(timer_time_.time_since_epoch().count()) {
			std::chrono::milliseconds span = std::chrono::duration_cast<std::chrono::milliseconds>(timer_time_ - std::chrono::steady_clock::now());
			int64_t span_count = span.count();
			if(span_count <= 0) {
				return 0;
			}
			if(span_count < wait_timeout_) {
				return span_count;
			}
		}
		return wait_timeout_;
	}

	virtual bool OnInit();

	virtual void OnTerm()
	{

	}

	virtual void OnNotify()
	{

	}

	virtual void OnWait()
	{

	}
	
	virtual void OnTimer()
	{

	}

	virtual void OnIdle()
	{

	}
	
	virtual void OnRun()
	{
		if(OnInit()) {
			while (!IsStopFlag()) {
				std::chrono::steady_clock::time_point tp = std::chrono::steady_clock::now();
				if(notify_flag_) {
					notify_flag_ = false;
					idle_flag_ = true;
					OnNotify();
				}
				if(IsStopFlag()) {
					break;
				}
				OnWait();
				if(IsStopFlag()) {
					break;
				}
				if(timer_time_.time_since_epoch().count()) {
					if(timer_time_ <= std::chrono::steady_clock::now()) {
						timer_time_ = std::chrono::steady_clock::time_point();
						OnTimer();
					}
				}
				if(idle_flag_) {
					if(IsStopFlag()) {
						break;
					}
					OnIdle(/*std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count()*/);
					if(IsStopFlag()) {
						break;
					}
					if(!wait_timeout_) {
						static const std::chrono::microseconds max_span(50);
						std::chrono::microseconds tp_span = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - tp);
						if(tp_span < max_span) {
							//std::this_thread::yield();
							//std::this_thread::sleep_for(std::chrono::nanoseconds(1));
							std::this_thread::sleep_for(max_span-tp_span);
						}
					}
				}
			}
		}
		OnTerm();
	}
};

/*!
 *	@brief TaskService 定义.
 *
 *	封装TaskService，实现简单事件服务
 */
template<class TBase/* = Service*/>
class TaskServiceT : public TBase
{
	typedef TBase Base;
public:
	struct TaskInfo
	{
		TaskInfo(std::function<void()> &&_task, void* _ptr = nullptr, size_t _delay = 0)
		:task(std::move(_task)), ptr(_ptr), time(std::chrono::steady_clock::now() + std::chrono::milliseconds(_delay)) {
			//PRINTF("Task");
		}
		TaskInfo(const TaskInfo& o):task(o.task),ptr(o.ptr),time(o.time) {
			//PRINTF("ltask");
		}
		TaskInfo(TaskInfo&& o):task(std::move(o.task)),ptr(o.ptr),time(o.time) {
			//PRINTF("rtask");
		}
		~TaskInfo() {
		}

		TaskInfo& operator = (const TaskInfo& rhs) {
			if(this == &rhs) return *this;
			ptr = rhs.ptr;
			task = rhs.task;
			time = rhs.time;
        	return *this;
    	}
		TaskInfo& operator = (TaskInfo&& rhs) {
			if(this == &rhs) return *this;
			ptr = rhs.ptr;
			task = std::move(rhs.task);
			time = rhs.time;
        	return *this;
    	}

		inline bool operator<(const TaskInfo& o) const
		{
			return time < o.time;
		}

		// inline void SetDelay(size_t millis) {
		// 	time = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
		// }
		//inline bool IsExecuted() { return !task; }

		inline bool IsActive(ssize_t* millis = nullptr) const {
			ssize_t diff = std::chrono::duration_cast<std::chrono::milliseconds>(time-std::chrono::steady_clock::now()).count();
			if(millis) {
				*millis = diff;
			}
			if(diff <= 0) {
				return true;
			}
			return false;
		}
		void* ptr = nullptr;
		std::function<void()> task;
		std::chrono::steady_clock::time_point time;
	};
protected:
	struct TaskInfoPtrLess
	{
		bool operator()(const std::shared_ptr<TaskInfo>& x, const std::shared_ptr<TaskInfo>& y) const
		{
			if(*x < *y) {
				return true;
			} else if(*y < *x) {
				return false;
			}
			return x < y;
		}
	};
	std::set<std::shared_ptr<TaskInfo>,TaskInfoPtrLess> tasks_;
	std::mutex mutex_;
public:
	
	inline std::shared_ptr<TaskInfo> Post(const std::shared_ptr<TaskInfo>& t)
	{
		if(!t) {
			return t;
		}
		std::lock_guard<std::mutex> lock(mutex_);
		tasks_.emplace(t);
#ifdef _DEBUG
		printf("task delay queue:");
		for(auto& tt : tasks_) {
			ssize_t delay = 0;
			tt->IsActive(&delay);
			printf("%d ", (int)delay);
		}
		printf("\n");
#endif//
		ssize_t delay = 0;
		if (!t->IsActive(&delay)) {
			Base::PostTimer(delay);
		} else {
			Base::PostNotify();	
		}
		return t;
	}

	inline void Cancel(const std::shared_ptr<TaskInfo>& t)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		tasks_.erase(t);
	}

	inline std::shared_ptr<TaskInfo> Post(size_t delay, void* ptr, std::function<void()> && task)
	{
		return Post(std::make_shared<TaskInfo>(std::move(task), ptr, delay));
	}

	inline std::shared_ptr<TaskInfo> Post(void* ptr, std::function<void()> && task)
	{
		return Post(0, ptr, std::move(task));
	}

	template<class F, class... Args>
	static inline std::function<void()> Package(std::future<typename std::result_of<F(Args...)>::type>& res, F&& f, Args&&... args)
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);

		res = task->get_future();

		return [task](){ (*task)(); };
	}

	inline void Cancel(void* ptr) {
		std::unique_lock<std::mutex> lock(mutex_);
		for(auto it = tasks_.begin(); it != tasks_.end(); )
		{
			const auto& t = *it;
			if (t->ptr == ptr) {
				it = tasks_.erase(it);
			} else {
				++it;
			}
		}
	}

protected:
	//
	inline void RemoveSocket(SocketEx* sock_ptr) {
		Cancel(sock_ptr);
	}

	void DoTask()
	{
		//从头开始消费
		std::unique_lock<std::mutex> lock(mutex_);
		size_t i = 0, j = tasks_.size();
		for(; i < j; i++)
		{
			auto it = tasks_.begin();
			auto t = *it;
			ssize_t delay = 0;
			if (t->IsActive(&delay)) {
				auto task(std::move(t->task));
				tasks_.erase(it);
				lock.unlock();
				task();
				lock.lock();
			} else {
				Base::PostTimer(delay);
				break;
			}
			if (tasks_.empty()) {
				break;
			}
		}
	}
	
	// virtual void OnIdle()
	// {
	// 	DoTask();
	// }
	
	virtual void OnNotify()
	{
		DoTask();
	}
	
	virtual void OnTimer()
	{
		DoTask();
	}
};

/*!
 *	@brief CVServiceT 模板定义.
 *
 *	封装CVServiceT，线程池
 */
template<class TBase = Service>
class CVServiceT : public TBase
{
	typedef TBase Base;
public:

	inline void Stop()
	{
		cv_.notify_one(); 
		Base::Stop();
	}
	
	inline void PostNotify() { 
		//std::lock_guard<std::mutex> lock(mutex_);
		Base::PostNotify();
		cv_.notify_one(); 
	}
	
protected:
	//
	virtual void OnWait()
	{
		size_t timeout = Base::GetWaitingTimeOut();
		if (timeout) {
			std::unique_lock<std::mutex> lock(mutex_);
			cv_.wait_for(lock, std::chrono::milliseconds(timeout));
		}
	}

protected:
	std::mutex mutex_;
	std::condition_variable cv_;
};

/*!
 *	@brief CVSocket 模板定义.
 *
 *	封装CVSocket
 */
template<class TSocketSet, class TBase = SocketEx>
class CVSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef TSocketSet SocketSet;
	typedef TSocketSet Service;
public:
	static SocketSet* service() { return dynamic_cast<SocketSet*>(SocketSet::service()); }
};

/*!
 *	@brief SocketService 定义.
 *
 *	封装SocketService，实现套接字和事件服务框架关联，这里需要使用者继承自enable_shared_from_this将SocketService对象添加到SocketSet里
 */
template<class TSocket, class TService = Service>
class SocketServiceT : public TSocket, public TService
{
public:
	typedef TSocket Socket;
	typedef TService Service;
public:

	void Start()
	{
		Service::Start();
		Socket::AttachService(this);
	}

	void Stop()
	{
		Socket::DetachService(this);
		Service::Stop();
	}

protected:
	//
	virtual void OnIdle()
	{
		if(Socket::IsSelect(FD_IDLE)) {
			Socket::RemoveSelect(FD_IDLE);
			Socket::OnIdle();
		}
		Service::OnIdle();
	}
};

/*!
 *	@brief Event 定义.
 *
 *	封装EventBase，定义事件对象接口
 */
class EventBase
{
public:
	inline bool IsActive(EventBase& evt) { return true; }
};

/*!
 *	@brief DealyEventBase 定义.
 *
 *	封装DealyEventBase，定义延迟事件
 */
class DealyEventBase
{
public:
	DealyEventBase(size_t _delay = 0, size_t _repeat = 0):time(std::chrono::steady_clock::now()),delay(_delay),repeat(_repeat){}
	DealyEventBase(const DealyEventBase& o):time(o.time),delay(o.delay),repeat(o.repeat){}
	//DealyEventBase(DealyEventBase&& o):time(o.time),delay(o.delay),repeat(o.repeat){}

	inline bool operator<(const DealyEventBase& o) const
    {
		return IsLess(o);
    }
	
	inline bool IsLess(const DealyEventBase& o) const { 
		if(!delay) {
			if(!o.delay) {
				if(repeat < o.repeat) {
					return true;
				} else {
					return false;
				}
			} else {
				return true;
			}
		} else {
			if(!o.delay) {
				return false;
			}
		}
		std::chrono::steady_clock::time_point tp = time + std::chrono::milliseconds(delay);
		std::chrono::steady_clock::time_point _tp = o.time + std::chrono::milliseconds(o.delay);
        if(tp < _tp) {
			return true;
		} else if(tp == _tp) {
			if(repeat < o.repeat) {
				return true;
			}
		}
		return false;
	} 

	inline bool IsActive(uint32_t* millis = nullptr) const {
		//PRINTF("IsActive delay=%d repeat=%d", delay.count(), repeat);
		if(delay > 0 && repeat >= 0) {
			uint32_t elapse = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-time).count();
			if(elapse > delay) {
				return true;
			}
			if(millis) {
				*millis = delay - elapse;
			}
			return false;
		}
		return true;
	}
	inline bool IsDelay() const {
		return delay > 0;
	}
	inline bool IsRepeat() const {
		return repeat > 0;
	}
	inline void Update() {
		if(delay > 0 && repeat > 0) {
			time = std::chrono::steady_clock::now();
			//dealy;
			if(repeat != (uint32_t)-1) {
				--repeat;
			}
		}
	}
	std::chrono::steady_clock::time_point time;
	uint32_t delay = 0;
	uint32_t repeat = 0;
};

/*!
 *	@brief EventService 定义.
 *
 *	封装EventService，实现事件服务接口
 */
template<class TEvent, class TBase = Service>
class EventServiceT : public TBase
{
	typedef TBase Base;
public:
	typedef TEvent Event;

protected:
	//
	inline SocketEx* IsSocketEvent(Event& evt) { return nullptr; }
	inline bool IsActive(Event& evt) { return true; }
};

/*!
 *	@brief ThreadServiceT 定义.
 *
 *	封装ThreadServiceT，实现线程服务服务
 */
template<class TBase = Service>
class ThreadServiceT : public TBase
{
	typedef ThreadServiceT<TBase> This;
	typedef TBase Base;
public:
	bool Start()
	{
		Stop();
		if(!Base::StartTest()) {
			return true; //说明其他线程调用Start了，这里直接返回true
		}
		Base::Start();
		thread_ptr_ = std::make_shared<std::thread>(std::bind(&This::OnRun,this));
		return true;
	}

	void Stop()
	{
		if(!Base::StopTest()) {
			return; //说明其他线程调用Stop了，这里直接返回
		}
		if(thread_ptr_) {
			thread_ptr_->join();
			thread_ptr_.reset();
		}
		Base::Stop();
	}

protected:
	//线程
	std::shared_ptr<std::thread> thread_ptr_;
};

typedef ThreadServiceT<Service> ThreadService;
typedef ThreadServiceT<CVServiceT<Service>> ThreadCVService;

/*!
 *	@brief ThreadPool 模板定义.
 *
 *	封装ThreadPool，线程池
 */
class ThreadPool
{
public:
	static ThreadPool& Inst() {
		static ThreadPool _inst(std::thread::hardware_concurrency() + 1);
		return _inst;
	}

	ThreadPool() : stop_flag_(true)
	{
		
	}
	ThreadPool(size_t threads) : stop_flag_(true)
	{
		Start(threads);
	}

	~ThreadPool()
	{
		Stop();
	}

	inline bool IsStopFlag() {
		return stop_flag_;
	}

	void Start(size_t threads)
	{
		bool expected = true;
		if (!stop_flag_.compare_exchange_strong(expected, false)) {
			return;
		}
		for (size_t i = 0; i < threads; ++i) {
			workers_.emplace_back(
				[this] {
					for (;;)
					{
						std::function<void()> task;
						{
							std::unique_lock<std::mutex> lock(mutex_);
							cv_.wait(lock,[this] { return stop_flag_ || !tasks_.empty(); });
							if (stop_flag_ && tasks_.empty())
								return;
							task = std::move(tasks_.front());
							tasks_.pop();
						}
						task();
					}
				});
		}
		//return true;
	}

	void Stop()
	{
		bool expected = false;
		if (!stop_flag_.compare_exchange_strong(expected, true)) {
			return;
		}
		cv_.notify_all();
		for (auto &worker : workers_) {
			worker.join();
		}
	}

	template<class F, class... Args>
	auto Post(F&& f, Args&&... args) 
		-> std::future<typename std::result_of<F(Args...)>::type>
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);
			
		std::future<return_type> res = task->get_future();
		{
			std::unique_lock<std::mutex> lock(mutex_);

			tasks_.emplace([task](){ (*task)(); });
		}
		cv_.notify_one();
		return res;
	}

private:
	std::atomic<bool> stop_flag_;
	std::vector<std::thread> workers_;
	std::queue<std::function<void()>> tasks_;
	std::mutex mutex_;
	std::condition_variable cv_;
};

/*!
 *	@brief WorkSocketT 模板定义.
 *
 *	封装WorkSocket，适用于服务端工作Socket
 */
template<class TBase = SocketEx>
class WorkSocketT : public TBase
{
	typedef TBase Base;
public:
	WorkSocketT():Base()
	{

	}
};

/*!
 *	@brief ConnectSocketT 模板定义.
 *
 *	封装ConnectSocket，适用于客户端连接Socket
 */
template<class TBase = SocketEx>
class ConnectSocketT : public TBase
{
	typedef ConnectSocketT<TBase> This;
	typedef TBase Base;
protected:
	bool connected_;
	size_t connect_time_;
	size_t connect_timeout_;

public:
	ConnectSocketT():Base(), connected_(false), connect_time_(0), connect_timeout_(0) {}
	//virtual ~ConnectSocketT() {}

	int Close()
	{
		int rlt = Base::Close();
		connected_ = false;
		connect_time_ = 0;
		return rlt;
	}

	void SetConnectTimeOut(size_t TimeOut)
	{
		connect_timeout_ = TimeOut;
	}

	size_t GetConnectTimeOut()
	{
		return connect_timeout_;
	}

	size_t GetConnectTime()
	{
		return connect_time_;
	}

	bool IsConnecting()
	{
		if(IsConnected()) {
			return false;
		}
		return connect_time_;
	}

	bool IsConnected()
	{
		return connected_;
	}

	bool IsConnectTimeOut() 
	{ 
		if(connect_timeout_ && (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() >= (connect_time_ + connect_timeout_))) {
			return true;
		}
		return false;
	}

protected:
	virtual void OnIdle()
	{
		Base::OnIdle();

		//ASSERT(IsConnectSocket());
		if(Base::IsSelect(FD_CONNECT) && connect_timeout_) {
			if(IsConnectTimeOut()) {
				OnConnect(ETIMEDOUT);
			}
		}
	}

	virtual void OnRole(int nRole)
	{
		Base::OnRole(nRole);

		//ASSERT(nRole==SOCKET_ROLE_CONNECT);
		connect_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
	}

	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);

		if(!nErrorCode) {
			connected_ = true;
			connect_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - connect_time_; //记住连接耗时
			Base::Select(FD_READ|FD_OOB);
		}
	}
};

/*!
 *	@brief ListenSocketT 模板定义.
 *
 *	封装ListenSocket，适用于服务端监听Socket
 */
template<class TBase>
class ListenSocketT : public TBase
{
	typedef TBase Base;
public:

	ListenSocketT():Base()
	{

	}

protected:
	//
	virtual void OnAccept(int nErrorCode)
	{
		if(nErrorCode) {
			return Base::OnAccept(nErrorCode);
		}

		//bool bConitnue = false;
		//do {
		//	bConitnue = false;
			SOCKADDR_STORAGE stAddr = {0};
			int nAddrLen = sizeof(stAddr);
			SOCKET Sock = Base::Accept((SOCKADDR*)&stAddr, &nAddrLen);
	 		if(XSocket::Socket::IsSocket(Sock)) {
				Base::Trigger(FD_ACCEPT, Sock, (const SOCKADDR*)&stAddr, nAddrLen);
				//bConitnue = true;
			} else {
				nErrorCode = XSocket::Socket::GetLastError();
				switch(nErrorCode)
				{
				case 0:
					break;
#ifdef WIN32
				case WSAEWOULDBLOCK:
				case WSA_IO_PENDING:
					break;
#else
				case EWOULDBLOCK:
					break;
				case EINTR:
					break;
#endif//
				default:
					Base::Trigger(FD_CLOSE,nErrorCode);
					break;
				}
			}
		//} while (bConitnue);
	}
};

/*!
 *	@brief HostSocketExT 模板定义.
 *
 *	封装HostSocketExT，支持字符串主机名套接字，自适应IPV4/IPV6套接字
 */
template<class TBase>
class HostSocketExT : public TBase
{
	typedef TBase Base;
protected:
	addrinfo* ai_current_ = nullptr;
public:
	HostSocketExT()
	{

	}
	virtual ~HostSocketExT() 
	{
	}

	inline SOCKET Open(const char* lpszHostAddress, int nSockAf = AF_UNSPEC, int nSockType = SOCK_STREAM)
	{
		struct addrinfo ai = {0};
		ai.ai_family = nSockAf;
		ai.ai_socktype = nSockType;
		ai.ai_flags = AI_PASSIVE;
		int ret = XSocket::Socket::GetAddrInfo(lpszHostAddress, nullptr, &ai, &ai_current_);
		if(ret) {
			PRINTLASTERROR("GetAddrInfo");
			return INVALID_SOCKET;
		}
		if(ai_current_) {
#ifdef _DEBUG
			for(addrinfo* ai_next = ai_current_; ai_next; ai_next = ai_next->ai_next)
			{
				char buf[64] = {0};
				PRINTF("%s", XSocket::Socket::SockAddr2IpStr(ai_next->ai_addr, ai_next->ai_addrlen, buf, 64));
			}
#endif
			return Base::Open(ai_current_->ai_family, ai_current_->ai_socktype, ai_current_->ai_protocol);
		}
		return INVALID_SOCKET;
	}

	inline SOCKET OpenNext()
	{
		if (ai_current_) {
			for(ai_current_ = ai_current_->ai_next; ai_current_; ai_current_ = ai_current_->ai_next)
			{
				return Base::Open(ai_current_->ai_family, ai_current_->ai_socktype, ai_current_->ai_protocol);
			}
		}
		return INVALID_SOCKET;
	}

	inline bool IsAddrLast() { return ai_current_ && ai_current_->ai_next ? false : true; }

	inline int GetAddrType() { ai_current_?ai_current_->ai_family:Base::GetAddrType(); }
};

/*!
 *	@brief ConnectSocketExT 模板定义.
 *
 *	封装ConnectSocketExT，自适应IPV4/IPV6套接字
 */
template<class TBase = SocketEx>
class ConnectSocketExT : public HostSocketExT<ConnectSocketT<TBase>>
{
	typedef HostSocketExT<ConnectSocketT<TBase>> Base;
public:
	ConnectSocketExT()
	{

	}
	virtual ~ConnectSocketExT() 
	{
	}

	inline int Connect(int nHostPort = 0)
	{
		ASSERT(Base::IsSocket());
		if (Base::ai_current_) {
			XSocket::Socket::SetAddrPort(Base::ai_current_->ai_addr, nHostPort);
			return Base::Connect(Base::ai_current_->ai_addr, Base::ai_current_->ai_addrlen);
		}
		return SOCKET_ERROR;
	}
};

/*!
 *	@brief ListenSocketExT 模板定义.
 *
 *	封装ListenSocketExT，自适应IPV4/IPV6套接字
 */
template<class TBase>
class ListenSocketExT : public HostSocketExT<ListenSocketT<TBase>>
{
	typedef HostSocketExT<ListenSocketT<TBase>> Base;
public:
	ListenSocketExT():Base()
	{

	}

	inline int Bind(int nHostPort = 0)
	{
		ASSERT (Base::IsSocket());
		if (Base::ai_current_) {
			XSocket::Socket::SetAddrPort(Base::ai_current_->ai_addr, nHostPort);
			return Base::Bind(Base::ai_current_->ai_addr, Base::ai_current_->ai_addrlen);
		}
		return SOCKET_ERROR;
	}
};

//////////////////////////////////////////////////////////////////////////

//DECLARE_HANDLE(HSOCKEX);		// An HSOCK	Handle

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief SocketSetT 模板定义.
 *
 *	封装SocketSet，实现最多管理uFD_SETSize数Socket
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class SocketSetT : public TService
{
	typedef TService Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
	//static const u_short SOCKET_SETSIZE = uFD_SETSize;
protected:
	u_short sock_count_ = 0;
	std::shared_ptr<Socket> sock_ptrs_[uFD_SETSize];
	//u_short sock_idle_next_ = 0;
	std::mutex mutex_;
public:
	SocketSetT()
	{
	}

	inline static const size_t GetMaxSocketCount() { return uFD_SETSize; }
	inline size_t GetSocketCount() { return sock_count_; }

	int AddSocket(std::shared_ptr<Socket> sock_ptr, int evt = 0)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]==NULL) {
				if (sock_ptr) {
					sock_count_++;
					sock_ptr->AttachService(this);
					sock_ptr->Select(evt);
					sock_ptrs_[i] = sock_ptr;
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
		ASSERT(sock_ptr);
		//std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]==sock_ptr) {
				return RemoveSocketByPos(i);
			}
		}
		return -1;
	}
	
	/*int RemoveInvalidSocket(std::shared_ptr<Socket> & sock_ptr)
	{
		//std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]) {
				std::unique_lock<std::mutex> lock(mutex_);
				std::shared_ptr<Socket> t_sock_ptr = sock_ptrs_[i];
				if (t_sock_ptr) {
					if (!t_sock_ptr->IsSocket() && !t_sock_ptr->IsSelect(-1)) {
						sock_ptrs_[i].reset();
						sock_count_--;
						sock_ptr = t_sock_ptr;
						sock_ptr->DetachService(this);
						Service::RemoveSocket(sock_ptr);
						return i;
						break;
					}
				}
			}
		}
		return -1;
	}*/
protected:
	//
	inline int RemoveSocketByPos(int i)
	{
		if (i>=0 && i<uFD_SETSize) {
			std::unique_lock<std::mutex> lock(mutex_);
			std::shared_ptr<Socket> sock_ptr = sock_ptrs_[i];
			if (sock_ptr) {
				sock_ptrs_[i].reset();
				sock_count_--;
				lock.unlock();
				sock_ptr->DetachService(this);
				Service::RemoveSocket(sock_ptr.get());
				return i;
			} else {
				return i;
			}
		}
		return -1;
	}

	void RemoveAllSocket(bool bClose = false)
	{
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if (sock_ptrs_[i]) {
				std::shared_ptr<Socket> sock_ptr = sock_ptrs_[i];
				sock_ptrs_[i].reset();
				if (sock_ptr->IsSocket()) {
					if (bClose) {
						sock_ptr->Trigger(FD_CLOSE, 0);
					}
				}
				sock_ptr->DetachService(this);
				Service::RemoveSocket(sock_ptr.get());
			}
		}
		sock_count_ = 0;
	}

	inline std::shared_ptr<Socket> FindSocket(SocketEx* sock_ptr) {
		if(sock_ptr) {
			int i;
			for (i=0;i<uFD_SETSize;i++)
			{
				if(sock_ptrs_[i].get()==sock_ptr) {
					return sock_ptrs_[i];
				}
			}
		}
		return nullptr;
	}

protected:
	//
	virtual void OnTerm()
	{
		//Service::OnTerm();
		RemoveAllSocket(true);
	}

	virtual void OnIdle()
	{
		Base::OnIdle();
		
		//int next = sock_idle_next_, next_end = sock_idle_next_ + 20;
		//sock_idle_next_ = next_end % uFD_SETSize;
		//for (; next < next_end; next++)
		//{
		//	int i = next % uFD_SETSize;
		int i = 0, j = 0;
		for (; i < uFD_SETSize && j <= 20; i++)
		{
			if (sock_ptrs_[i]) {
				std::shared_ptr<Socket> sock_ptr = sock_ptrs_[i];
				if (sock_ptr) {
					if(sock_ptr->IsSelect(FD_IDLE)) {
						j++;
						sock_ptr->RemoveSelect(FD_IDLE);
						sock_ptr->Trigger(FD_IDLE
						//, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
						, 0
						);
					}
					if (!sock_ptr->IsSocket()) {
						if(!sock_ptr->IsSelect(-1)) { 
							//自动移除
							RemoveSocketByPos(i);
						}
					}
				}
			}
		}
	}
};

/*!
 *	@brief SocketManagerT 模板定义.
 *
 *	封装SocketManager，实现对管理多个SocketSet，可以支持任意数Socket
 */
template<class TSocketSet>
class SocketManagerT
{
public:
	typedef TSocketSet SocketSet;
	typedef typename TSocketSet::Socket Socket;
protected:
	std::vector<SocketSet*> sockset_ptrs_;
	size_t sockset_add_next_ = 0;
public:
	SocketManagerT(int nMaxSockSetCount)
	{
		sockset_ptrs_.resize(nMaxSockSetCount,NULL);
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i] = new SocketSet();
		}
		sockset_add_next_ = 0;
	}

	~SocketManagerT() 
	{
		for (size_t i=0,j=sockset_ptrs_.size();i<j;i++)
		{
			delete sockset_ptrs_[i];
		}
		sockset_ptrs_.clear();
		sockset_add_next_ = 0;
	}

	bool Start()
	{
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i]->Start();
		}
		return true;
	}

	void Stop()
	{
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i]->Stop();
		}
	}

	inline void SetWaitTimeOut(size_t millis) { 
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i]->SetWaitTimeOut(millis);
		}
	}
	inline size_t GetWaitTimeOut() { 
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			return sockset_ptrs_[i]->GetWaitTimeOut();
		}
		return 0; 
	}

	inline size_t GetSocketSetCount() { return sockset_ptrs_.size(); }
	inline size_t GetMaxSocketCount() { 
		return sockset_ptrs_.size() * SocketSet::GetMaxSocketCount(); 
	}
	inline size_t GetSocketCount() { 
		size_t count = 0;
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			count += sockset_ptrs_[i]->GetSocketCount();
		}
		return count; 
	}

	inline SocketSet* GetSocketSet(size_t pos) {
		if(pos < sockset_ptrs_.size())
			return sockset_ptrs_[pos];
		return nullptr;
	}

	inline int AddSocket(std::shared_ptr<Socket> sock_ptr, int evt = 0)
	{
		size_t next = sockset_add_next_, next_end = sockset_add_next_ + sockset_ptrs_.size();
		sockset_add_next_ = (sockset_add_next_ + 1) % sockset_ptrs_.size();
		for (; next < next_end; next++)
		{
			int i = next % sockset_ptrs_.size();
			int result = sockset_ptrs_[i]->AddSocket(sock_ptr, evt);
			if (result >= 0) {
				return i;
				break;
			}
		}
		return -1;
	}
	inline int AddConnect(std::shared_ptr<Socket> sock_ptr, u_short port)
	{
		size_t next = sockset_add_next_, next_end = sockset_add_next_ + sockset_ptrs_.size();
		sockset_add_next_ = (sockset_add_next_ + 1) % sockset_ptrs_.size();
		for (; next < next_end; next++)
		{
			int i = next % sockset_ptrs_.size();
			int result = sockset_ptrs_[i]->AddConnect(sock_ptr, port);
			if (result >= 0) {
				return i;
				break;
			}
		}
		return -1;
	}
	inline int AddAccept(std::shared_ptr<Socket> sock_ptr)
	{
		size_t next = sockset_add_next_, next_end = sockset_add_next_ + sockset_ptrs_.size();
		sockset_add_next_ = (sockset_add_next_ + 1) % sockset_ptrs_.size();
		for (; next < next_end; next++)
		{
			int i = next % sockset_ptrs_.size();
			int result = sockset_ptrs_[i]->AddAccept(sock_ptr);
			if (result >= 0) {
				return i;
				break;
			}
		}
		return -1;
	}

	inline int RemoveSocket(std::shared_ptr<Socket> sock_ptr)
	{
		for (size_t i=0,j=sockset_ptrs_.size();i<j;i++)
		{
			int result = sockset_ptrs_[i]->RemoveSocket(sock_ptr);
			if (result >= 0) {
				return i;
				break;
			}
		}
		return -1;
	}

	/*int RemoveInvalidSocket(std::shared_ptr<Socket> & sock_ptr)
	{
		for (size_t i=0,j=sockset_ptrs_.size();i<j;i++)
		{
			int result = sockset_ptrs_[i]->RemoveInvalidSocket(sock_ptr);
			if (result >= 0) {
				return i;
				break;
			}
		}
		return -1;
	}

	void RemoveAllSocket(bool bClose = false)
	{
		int i,j;
		for (i=0,j=sockset_ptrs_.size();i<j;i++)
		{
			sockset_ptrs_[i]->RemoveAllSocket(bClose);
		}
	}*/

protected:
};

/*!
 *	@brief SelectServiceT 模板定义.
 *
 *	封装SelectServiceT
 */
template<class TService = Service>
class SelectServiceT : public TService
{
	typedef TService Base;
public:
	typedef TService Service;
public:
};

typedef ThreadServiceT<SelectServiceT<Service>> SelectService;

/*!
 *	@brief SelectSvrSocket 模板定义.
 *
 *	封装SelectSvrSocket，实现对select模型管理一个客户端连接Socket
 */
template<class TService = SelectService, class TBase = SocketEx>
class SelectOneSocketT : public SocketServiceT<TBase,TService>
{
	typedef SelectOneSocketT<TService,TBase> This;
	typedef SocketServiceT<TBase,TService> Base;
public:
	SelectOneSocketT() : Base()
	{
    	
	}

protected:
	//
	virtual void OnWait()
	{
		struct timeval tv = {0, Service::GetWaitingTimeOut()*1000};
		if(!Base::IsSocket()) {
			if(tv.tv_usec)
				std::this_thread::sleep_for(std::chrono::microseconds(tv.tv_usec));
			return;
		}

		int fd = *this;
		int nfds = 0;
		int maxfds = 0;
		fd_set exceptfds;
		FD_ZERO(&exceptfds);
		maxfds = fd + 1;
		FD_SET(fd, &exceptfds);
		if (Base::IsListenSocket()) {
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(fd, &readfds);
			nfds = select(maxfds, &readfds, NULL, &exceptfds, &tv);
			if (nfds > 0) {
				if (FD_ISSET(fd,&readfds)) {
					if (Base::IsSelect(FD_ACCEPT)) {
						Base::Trigger(FD_ACCEPT, 0);
					}
				}
				if (FD_ISSET(fd, &exceptfds)) {
					int nErrorCode = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
					if (nErrorCode == 0) {
						nErrorCode = Base::GetLastError();
					}
					if (nErrorCode == 0) {
						nErrorCode = ENETDOWN;
					}
					//SetLastError(nErrorCode);
					Base::Trigger(FD_ACCEPT, nErrorCode);
				}
			}
		} else if (Base::IsSelect(FD_CONNECT)) {
			fd_set writefds;
			FD_ZERO(&writefds);
			maxfds = fd + 1;
			FD_SET(fd, &writefds);
			nfds = select(maxfds, NULL, &writefds, &exceptfds, &tv);
			if (nfds > 0) {
				if (FD_ISSET(fd, &writefds)) {
					Base::RemoveSelect(FD_CONNECT);
					int nErrorCode = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
					Base::Trigger(FD_CONNECT, nErrorCode);
					if (Base::IsSocket() && Base::IsSelect(FD_WRITE)) {
						Base::Trigger(FD_WRITE, 0);
					}
					if (Base::IsSocket() && Base::IsSelect(FD_READ)) {
						Base::Trigger(FD_READ, 0);
					}
				}
				if (FD_ISSET(fd, &exceptfds)) {
					Base::RemoveSelect(FD_CONNECT);
					int nErrorCode = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
					if (nErrorCode == 0) {
						nErrorCode = ENETDOWN;
					}
					//SetLastError(nErrorCode);
					Base::Trigger(FD_CONNECT, nErrorCode);
				}
			}
		} else {
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(fd, &readfds);
			fd_set writefds;
			FD_ZERO(&writefds);
			FD_SET(fd, &writefds);
			nfds = select(maxfds, &readfds, &writefds, &exceptfds, &tv);
			if (nfds > 0) {
				if (FD_ISSET(fd,&readfds)) {
					int err = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_OOBINLINE, &err, sizeof(err));
					if (err) {
						if (Base::IsSelect(FD_OOB)) {
							Base::Trigger(FD_OOB, 0);
						}
					} else {
						if (Base::IsSelect(FD_READ)) {
							Base::Trigger(FD_READ, 0);
						}
					}
				}
				if (FD_ISSET(fd, &writefds)) {
					if (Base::IsSelect(FD_WRITE)) {
						Base::Trigger(FD_WRITE, 0);
					}
				}
				if (FD_ISSET(fd, &exceptfds)) {
					int nErrorCode = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
					if (nErrorCode == 0) {
						nErrorCode = ENETDOWN;
					}
					//SetLastError(nErrorCode);
					Base::Trigger(FD_CLOSE, nErrorCode);
				}
			}
		}
	}
};

/*!
 *	@brief SelectSocket 模板定义.
 *
 *	封装SelectSocket
 */
template<class TSocketSet, class TBase = SocketEx>
class SelectSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef TSocketSet SocketSet;
public:
	static SocketSet* service() { return dynamic_cast<SocketSet*>(SocketSet::service()); }

	SelectSocketT() : Base()
	{
    	
	}

	// inline void Select(int lEvent) {  
	// 	int lAsyncEvent = 0;
	// 	if(!Base::IsSelect(FD_IDLE) && (lEvent & FD_IDLE)) {
	// 		lAsyncEvent |= FD_IDLE;
	// 	}
	// 	Base::Select(lEvent);
	// 	if(lAsyncEvent) {
	// 		service()->SelectSocket(this,lAsyncEvent);
	// 	}
	// }
};

/*!
 *	@brief SelectSocketSet 模板定义.
 *
 *	封装SelectSocketSet，实现对select模型封装，最多管理uFD_SETSize数Socket
 */
template<class TService = SelectService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class SelectSocketSetT : public SocketSetT<TService,TSocket,uFD_SETSize>
{
	typedef SocketSetT<TService,TSocket,uFD_SETSize> Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
public:
	SelectSocketSetT()
	{
		
	}

protected:
	//
	virtual void OnWait()
	{
		int nfds = 0;
		int maxfds = 0;
		fd_set exceptfds;
		FD_ZERO(&exceptfds);
		fd_set readfds;
		FD_ZERO(&readfds);
		fd_set writefds;
		FD_ZERO(&writefds);
		struct timeval tv = {0, Base::GetWaitingTimeOut()*1000};
		std::unique_lock<std::mutex> lock(Base::mutex_);
		{
			for (size_t i=0; i<uFD_SETSize; ++i)
			{
				if (Base::sock_ptrs_[i] && Base::sock_ptrs_[i]->IsSocket()) {
					nfds++;
					FD_SET(*Base::sock_ptrs_[i], &exceptfds);
					if(Base::sock_ptrs_[i]->IsSelectRead()) {
						if(maxfds<(*Base::sock_ptrs_[i]+1)) {
							maxfds = (*Base::sock_ptrs_[i]+1);
						}
						FD_SET(*Base::sock_ptrs_[i], &readfds);
					} 
					if(Base::sock_ptrs_[i]->IsSelectWrite()) {
						if(maxfds<(*Base::sock_ptrs_[i]+1)) {
							maxfds = (*Base::sock_ptrs_[i]+1);
						}
						FD_SET(*Base::sock_ptrs_[i], &writefds);
					}
				}
			}
			lock.unlock();
		}
		if(nfds > 0)
			nfds = select(maxfds, &readfds, &writefds, &exceptfds, &tv);
		else if(tv.tv_usec)
			std::this_thread::sleep_for(std::chrono::microseconds(tv.tv_usec));
		if (nfds > 0) {
			for (size_t i = 0; i < uFD_SETSize; ++i)
			{
				if (Base::sock_ptrs_[i]) {
					lock.lock();
					std::shared_ptr<Socket> sock_ptr = Base::sock_ptrs_[i];
					lock.unlock();
					if (sock_ptr) {
						if (FD_ISSET(*sock_ptr, &readfds)) {
							if (sock_ptr->IsListenSocket()) {
								sock_ptr->Trigger(FD_ACCEPT, 0);
							} else {
								int err = 0;
								sock_ptr->GetSockOpt(SOL_SOCKET, SO_OOBINLINE, &err, sizeof(err));
								if (err) {
									if(sock_ptr->IsSelect(FD_OOB)) {
										sock_ptr->Trigger(FD_OOB, 0);
									}
								} else {
									if(sock_ptr->IsSelect(FD_READ)) {
										sock_ptr->Trigger(FD_READ, 0);
									}
								}
							}
						}
						if (FD_ISSET(*sock_ptr, &writefds)) {
							if (sock_ptr->IsSelect(FD_CONNECT)) {
								sock_ptr->RemoveSelect(FD_CONNECT);
								int nErrorCode = 0;
								sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, &nErrorCode, sizeof(nErrorCode));
								sock_ptr->Trigger(FD_CONNECT, nErrorCode);
								if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_WRITE)) {
									sock_ptr->Trigger(FD_WRITE, 0);
								}
								if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_READ)) {
									sock_ptr->Trigger(FD_READ, 0);
								}
							} else if(sock_ptr->IsSelect(FD_WRITE)) {
								sock_ptr->Trigger(FD_WRITE, 0);
							}
						}
						if (FD_ISSET(*sock_ptr, &exceptfds)) {
							int nErrorCode = 0;
							sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
							if(nErrorCode == 0) {
								nErrorCode = sock_ptr->GetLastError();
							}
							if (nErrorCode == 0) {
								nErrorCode = ENETDOWN;
							}
							//sock_ptr->SetLastError(nErrorCode);
							if (sock_ptr->IsListenSocket()) {
								sock_ptr->Trigger(FD_ACCEPT, nErrorCode);
							} else if(sock_ptr->IsSelect(FD_CONNECT)) {
								sock_ptr->RemoveSelect(FD_CONNECT);
								sock_ptr->Trigger(FD_CONNECT, nErrorCode);
							} else {
								sock_ptr->Trigger(FD_CLOSE, nErrorCode);
							}
						}
					}
				}
			}
		} else if (nfds == 0) {
			//
		} else {
			//
		}
	}
};

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief SelectClient 模板定义.
 *
 *	封装SelectClient，实现对select模型管理一个客户端Tcp Socket
 */
template<class TService = ThreadService, class TBase = ConnectSocketT<SocketEx>> 
class SelectClientT : public SelectOneSocketT<TService,TBase>
{
	typedef SelectOneSocketT<TService,TBase> Base;
public:
	SelectClientT():Base()
	{
		
	}
	virtual ~SelectClientT()
	{
		
	}

protected:
};


/*!
 *	@brief SelectServer 模板定义.
 *
 *	封装SelectServer，实现对select模型管理监听Socket连接，依赖SelectSet/SelectManager
 */
template<class TService, class TBase, class TSocketSet>
class SelectServerT 
: public SelectOneSocketT<TService,TBase>
, public SocketManagerT<TSocketSet>
{
public:
	typedef TSocketSet SocketSet;
	typedef typename SocketSet::Socket Socket;
	typedef SocketManagerT<SocketSet> SockManager;
	typedef SelectOneSocketT<TService,TBase> Base;
protected:
	std::string address_;
	u_short port_;
public:
	SelectServerT(int nMaxSocketCount) : Base(),SockManager((nMaxSocketCount+SocketSet::GetMaxSocketCount()-1)/SocketSet::GetMaxSocketCount())
	{
		
	}

	~SelectServerT()
	{
		
	}

	inline void SetWaitTimeOut(size_t millis) { SockManager::SetWaitTimeOut(millis); Base::SetWaitTimeOut(millis); }
	inline size_t GetWaitTimeOut() { return Base::GetWaitTimeOut(); }

	bool Start(const char* address, u_short port)
	{
		address_ = address;
		port_ = port;
		if(!SockManager::Start()) {
			return false;
		}
		Base::Start();
		return true;
	}

	void Stop()
	{
		Base::Stop();
		SockManager::Stop();
	}

protected:
	//
	virtual bool OnInit()
	{
		if(port_ <= 0) {
			return false;
		}
		Base::Open(AF_INET);
		Base::SetSockOpt(SOL_SOCKET, SO_REUSEADDR, 1);
		SOCKADDR_IN stAddr = {0};
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = XSocket::Socket::Ip2N(XSocket::Socket::Url2Ip((char*)address_.c_str()));
		stAddr.sin_port = htons((u_short)port_);
		Base::Bind((SOCKADDR*)&stAddr, sizeof(stAddr));
		Base::Listen();
		return true;
	}

	virtual void OnTerm()
	{
		//服务结束运行，释放资源
		if(Base::IsSocket()) {
#ifndef WIN32
			Base::ShutDown();
#endif
			Base::Trigger(FD_CLOSE, 0);
		}
	}

	virtual void OnAccept(SOCKET Sock, const SOCKADDR* lpSockAddr, int nSockAddrLen) 
	{
				//测试下还能不能再接收SOCKET
				if(SockManager::AddSocket(NULL) < 0) {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.");
					XSocket::Socket::Close(Sock);
					return;
				}
				std::shared_ptr<Socket> sock_ptr = std::make_shared<Socket>();
				sock_ptr->Attach(Sock,SOCKET_ROLE_WORK);
				sock_ptr->SetNonBlock();//设为非阻塞模式
				int pos = SockManager::AddSocket(sock_ptr, FD_READ|FD_OOB);
				if(pos >= 0) {
					//
				} else {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.");
					sock_ptr->Trigger(FD_CLOSE, 0);
				}
	}
};

/*!
 *	@brief SelectUdpClient 模板定义.
 *
 *	封装SelectUdpClient，实现对select模型管理一个客户端Udp Socket
 */
template<class TService = ThreadService, class TBase = SocketEx> 
class SelectUdpClientT : public SelectOneSocketT<TService,TBase>
{
	typedef SelectOneSocketT<TService,TBase> Base;
public:
	SelectUdpClientT():Base()
	{

	}
	virtual ~SelectUdpClientT()
	{
		
	}

protected:
};

/*!
 *	@brief SelectUdpServer 模板定义.
 *
 *	封装SelectUdpServer，实现对select模型管理一个服务端Udp Socket
 */
template<class TService = ThreadService, class TBase = SocketEx>
class SelectUdpServerT : public SelectOneSocketT<TService,TBase>
{
	typedef SelectOneSocketT<TService,TBase> Base;
public:
	SelectUdpServerT():Base()
	{

	}
	virtual ~SelectUdpServerT()
	{
		
	}

protected:
};

}

#endif//_H_XSOCKETEX_H_
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

#ifndef _H_XSOCKETEX_H_
#define _H_XSOCKETEX_H_

#include <atomic>
#include <mutex>
#ifndef WIN32
#include <condition_variable>
#endif
#include <thread>
#include <functional>
#include <algorithm>
#include <vector>
#include <queue>
#include <set>
#include <chrono>
#include "XSocket.h"

namespace XSocket {

	class SocketEx;
	class Service;

const uint32_t MAX_SOCK_COUNT =	(u_short)(-1);

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
 *	@brief 可伸缩的Socket封装.
 *
 *	SocketEx定义了可伸缩Socket的接口和基本实现
 */
class XSOCKET_API SocketEx : public Socket
{
public:
	SocketEx();
	virtual ~SocketEx();

	//只需重载Attach，因为Open和Detach都会调用Attach
	SOCKET Open(int nSockAf = AF_INET, int nSockType = SOCK_STREAM);
	SOCKET Attach(SOCKET Sock, int Role = SOCKET_ROLE_NONE);
	SOCKET Detach();

	int ShutDown(int nHow = Both);
	int Close();

	SOCKET Accept(SOCKADDR* lpSockAddr, int* lpSockAddrLen);
	//int Bind(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy);
	int Bind(const char* lpszHostAddress, unsigned short nHostPort);
	int Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen);
	//int Connect(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy);
	int Connect(const char* lpszHostAddress, unsigned short nHostPort);
	int Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen);
	int Listen(int nConnectionBacklog = 5);

	int Send(const char* lpBuf, int nBufLen, int nFlags = 0);
	int Receive(char* lpBuf, int nBufLen, int nFlags = 0);
	int SendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags = 0);
	int ReceiveFrom(char* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags = 0);

	inline int Role() { return m_Role; }
	inline bool IsNoneRole() { return	Role()==SOCKET_ROLE_NONE; }
	inline bool IsConnectSocket() { return Role()==SOCKET_ROLE_CONNECT; }
	inline bool IsListenSocket() { return Role()==SOCKET_ROLE_LISTEN; }
	inline bool IsWorkSocket() { return Role()==SOCKET_ROLE_WORK; }

	inline void AttachService(Service* svr) { OnAttachService(svr); }
	inline void DetachService(Service* svr) { OnDetachService(svr); }
	
	inline void Select(int lEvent) { m_lEvent |= lEvent; }
	inline void RemoveSelect(int lEvent) { m_lEvent &= ~lEvent; }
	inline bool IsSelect(int evt, bool all = false) {
		if(all) {
			return m_lEvent & evt == evt;
		} 
		return m_lEvent & evt;
	}
	inline bool IsSelectRead() { return IsSelect(FD_READ|FD_OOB|FD_ACCEPT); }
	inline bool IsSelectWrite() { return IsSelect(FD_WRITE|FD_CONNECT); }

	inline void Trigger(int evt, int nErrorCode) { 
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
		case FD_IDLE:
			OnIdle(nErrorCode);
			break;
		default:
			break;
		}
	}
	
	inline void Trigger(int evt, const char* lpBuf, int nBufLen, int nFlags) { 
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
			OnAccept((const SOCKADDR *)lpBuf, nBufLen, (SOCKET)nFlags);
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
	virtual void OnAttachService(Service* pSvr){}
	virtual void OnDetachService(Service* pSvr){}

	/*!
	 *	@brief 通知套接字无可操作状态，正在空闲或者等待中.
	 *
	 *	OnIdle函数是后台在计算空闲的情况，给SocketEx用于做一些空闲处理动作，比如检查超时
	 *	、清理垃圾数据等等
	 *	@param nErrorCode 标示进入空闲时间，可以使用GetTickCount()-nErrorCode计算OnIdle耗时
	 */
	virtual void OnIdle(int nErrorCode);

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
	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags) {}
	
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
	virtual void OnSend(const char* lpBuf, int nBufLen, int nFlags) {}
	
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
	virtual void OnOOB(const char* lpBuf, int nBufLen, int nFlags) {}

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
	virtual void OnAccept(const SOCKADDR* lpSockAddr, int nSockAddrLen, SOCKET Sock) {}

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
	uint8_t m_Role;
	uint8_t m_lEvent;

private:
	SocketEx(const SocketEx& Sock) {};
	void operator=(const SocketEx& Sock) {};
};

	template <class Ty>
	class Queue
	{
	public:
		Queue() { }
		Queue(const Queue<Ty>&) = delete;
		Queue& operator=(const Queue<Ty>&) = delete;
		~Queue() { 
#ifdef _DEBUG
			std::lock_guard<std::mutex> lock(mutex_);
			assert(queue_.empty()); 
#endif
		}

		void push(const Ty& o)
		{
			std::lock_guard<std::mutex> lock(mutex_);
			queue_.push(o);
			//if (timeout_) {
				cv_.notify_one();
			//}
		}
		bool pop(Ty& o, size_t timeout = 0)
		{
			std::unique_lock<std::mutex> lock(mutex_);
			if(queue_.empty()) {
				if (timeout) {
					if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout),
						[this]() { return !queue_.empty(); })) { 
						return false; 
					}
				} else {
					return false;
				}
			} 
			o = queue_.front();
			queue_.pop();
			return true;
		}
		size_t size()
		{
			return queue_.size();
		}
		bool empty()
		{
			return queue_.empty();
		}
	private:
		std::queue<Ty> queue_;
		std::mutex mutex_;
		std::condition_variable cv_;
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
public:
	static Service* service();

	Service();

	inline bool IsStopFlag() {
		return stop_flag_;
	}

	virtual void AsyncSelect(SocketEx* sock_ptr, int evt) {
		sock_ptr->Select(evt);
	}

protected:
	//
	virtual void OnRun()
	{
		if(OnInit()) {
			while (!IsStopFlag()) {
				size_t tick_count = Tick();
				OnRunOnce();
				if(IsStopFlag()) {
					break;
				}
				//size_t tick_span = Tick() - tick_count;
				//if(tick_span < 20 || tick_span > 100) {
					OnIdle(Tick());
					if(IsStopFlag()) {
						break;
					}
					size_t tick_span = Tick() - tick_count;
					if(tick_span < 20) {
						//std::this_thread::yield();
						std::this_thread::sleep_for(std::chrono::milliseconds(20-tick_span));
					}
				//}
			}
		}
		OnTerm();
	}

	virtual bool OnInit();

	virtual void OnTerm()
	{

	}

	virtual void OnRunOnce()
	{
		
	}

	virtual void OnIdle(int nErrorCode)
	{

	}
};

/*!
 *	@brief ConnectSocket 模板定义.
 *
 *	封装ConnectSocket，适用于客户端连接Socket
 */
template<class TBase = SocketEx>
class ConnectSocket : public TBase
{
	typedef ConnectSocket<TBase> This;
	typedef TBase Base;
protected:
	bool m_bConnected;
	unsigned long m_ConnectTime;
	unsigned long m_ConnectTimeOut;

public:
	ConnectSocket():Base(), m_bConnected(false), m_ConnectTime(0), m_ConnectTimeOut(0) {}
	//virtual ~SocketConnectTimeOut() {}

	int Close()
	{
		int rlt = Base::Close();
		m_bConnected = false;
		m_ConnectTime = 0;
		return rlt;
	}

	bool IsConnecting()
	{
		if(IsConnected()) {
			return false;
		}
		return m_ConnectTime;
	}

	bool IsConnected()
	{
		return m_bConnected;
	}

	void SetConnectTimeOut(unsigned long TimeOut)
	{
		m_ConnectTimeOut = TimeOut;
	}

	unsigned long GetConnectTimeOut()
	{
		return m_ConnectTimeOut;
	}

	bool IsConnectTimeOut() 
	{ 
		if(m_ConnectTimeOut && (Tick() >= (m_ConnectTime + m_ConnectTimeOut))) {
			return true;
		}
		return false;
	}

	unsigned long GetConnectTime()
	{
		return m_ConnectTime;
	}

protected:
	virtual void OnIdle(int nErrorCode)
	{
		Base::OnIdle(nErrorCode);

		//ASSERT(IsConnectSocket());
		if(Base::IsSelect(FD_CONNECT) && m_ConnectTimeOut) {
			if(IsConnectTimeOut()) {
				OnConnect(ETIMEDOUT);
			}
		}
	}

	virtual void OnRole(int nRole)
	{
		Base::OnRole(nRole);

		//ASSERT(nRole==SOCKET_ROLE_CONNECT);
		m_ConnectTime = Tick();
	}

	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);

		if(!nErrorCode) {
			m_bConnected = true;
			m_ConnectTime = Tick() - m_ConnectTime; //记住连接耗时
			Base::Select(FD_READ|FD_WRITE|FD_OOB);
		}
	}
};

/*!
 *	@brief WorkSocket 模板定义.
 *
 *	封装WorkSocket，适用于服务端工作Socket
 */
template<class TBase = SocketEx>
class WorkSocket : public TBase
{
	typedef TBase Base;
public:
	WorkSocket():Base()
	{

	}

protected:
	//
	virtual void OnAttachService(Service* pSvr)
	{
		
	}
};

/*!
 *	@brief ListenSocket 模板定义.
 *
 *	封装ListenSocket，适用于服务端监听Socket
 */
template<class TBase = SocketEx>
class ListenSocket : public TBase
{
	typedef TBase Base;
public:
	ListenSocket():Base()
	{

	}

protected:
};


/*!
 *	@brief EventService 定义.
 *
 *	封装EventService，实现事件服务框架
 */
template<class TEvent, class TBase = Service>
class EventService : public TBase
{
	typedef TBase Base;
public:
	typedef TEvent Event;
protected:
	Queue<Event> queue_;
public:

	inline void Post(const Event& evt) {
		queue_.push(evt);
	}

protected:
	virtual void OnEvent(const Event& evt)
	{
		
	}

	virtual void OnRunOnce()
	{
		Event evt;
		for(size_t i = 0, j = queue_.size(); i < j; i++)
		{
			if (queue_.pop(evt)) {
				OnEvent(evt);
			}
		}
	}
};

/*!
 *	@brief DealyEvent 定义.
 *
 *	封装DealyEvent，定义延迟事件
 */
template<class TEvent>
class DealyEvent : public TEvent
{
	typedef TEvent Base;
public:
	typedef TEvent Event;
public:
	DealyEvent():Base(){}
	DealyEvent(Event evt):Base(evt){}
	DealyEvent(Event evt, size_t _delay, size_t _repeat):Base(evt),time(std::chrono::steady_clock::now()),delay(_delay),repeat(_repeat){}
	DealyEvent(const DealyEvent& o):Base((Event)o),time(o.time),delay(o.delay),repeat(o.repeat){}
	inline bool IsPoint()
	{
		if(delay.count() > 0 && repeat >= 0) {
			if((std::chrono::steady_clock::now()-time) > delay) {
				return true;
			}
			return false;
		}
		return true;
	}
	inline bool IsRepeat()
	{
		return repeat > 0;
	}
	inline void Update() {
		if(delay.count() > 0 && repeat > 0) {
			time = std::chrono::steady_clock::now();//std::chrono::microseconds(evt.millis);
			//dealy;
			if(repeat == (size_t)-1) {
				--repeat;
			}
		}
	}
	std::chrono::steady_clock::time_point time;
	std::chrono::milliseconds delay;
	int repeat = 0;
};
/*!
 *	@brief DelayEventService 定义.
 *
 *	封装DelayEventService，实现延迟事件服务
 */
template<class TEvent, class TBase = Service>
class DelayEventService : public EventService<DealyEvent<TEvent>,TBase>
{
	typedef EventService<DealyEvent<TEvent>,TBase> Base;
public:
	typedef TEvent Event;
	typedef DealyEvent<TEvent> DelayEvent;
public:
	
	inline void Post(const Event& evt) {
		PostDelay(evt);
	}

	inline void PostDelay(const Event& evt, size_t mills = 0, size_t repeat = 0) {
		if(mills) {
			Base::queue_.push(DelayEvent(evt,mills,repeat));
		} else {
			Base::queue_.push(DelayEvent(evt));
		}
	}

protected:

	virtual void OnEvent(const Event& evt)
	{
		
	}

	virtual void OnRunOnce()
	{
		DelayEvent evt;
		for(size_t i = 0, j = Base::queue_.size(); i < j; i++)
		{
			if (Base::queue_.pop(evt)) {
				if(evt.IsPoint()) {
					OnEvent(evt);
					evt.Update();
					if(evt.IsRepeat()) {
						Base::queue_.push(evt);
					}
				} else {
					Base::queue_.push(evt);
				}
			} else {
				break;
			}
		}
	}
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
		bool expected = true;
		if (!Base::stop_flag_.compare_exchange_strong(expected, false)) {
			return true;
		}
		thread_ptr_ = std::make_shared<std::thread>(std::bind(&This::OnRun,this));
		return true;
	}

	void Stop()
	{
		bool expected = false;
		if (!Base::stop_flag_.compare_exchange_strong(expected, true)) {
			return;
		}
		if(thread_ptr_) {
			thread_ptr_->join();
			thread_ptr_.reset();
		}
	}

protected:
	//线程
	std::shared_ptr<std::thread> thread_ptr_;
};

typedef ThreadServiceT<Service> ThreadService;

//////////////////////////////////////////////////////////////////////////

//DECLARE_HANDLE(HSOCKEX);		// An HSOCK	Handle

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief SocketSet 模板定义.
 *
 *	封装SocketSet，实现最多管理uFD_SETSize数Socket
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class SocketSet : public TService
{
public:
	typedef TService Service;
	typedef TSocket Socket;
	//static const u_short SOCKET_SETSIZE = uFD_SETSize;
protected:
	u_short sock_count_;
	Socket* sock_ptrs_[uFD_SETSize];
	u_short sock_idle_next_;
	std::mutex mutex_;
public:
	SocketSet()
	{
		sock_count_ = 0;
		memset(sock_ptrs_,0,sizeof(sock_ptrs_));
		sock_idle_next_ = 0;
	}

	inline static const size_t GetMaxSocketCount() { return uFD_SETSize; }
	inline size_t GetSocketCount() { return sock_count_; }

	int AddSocket(Socket* sock_ptr, int evt = 0)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]==NULL) {
				if (sock_ptr) {
					sock_ptr->AttachService(this);
					sock_ptr->Select(evt);
					sock_count_++;
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

	int RemoveSocket(Socket* sock_ptr)
	{
		ASSERT(sock_ptr);
		//std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]==sock_ptr) {
				std::unique_lock<std::mutex> lock(mutex_);
				TSocket* t_sock_ptr = sock_ptrs_[i];
				if (t_sock_ptr) {
					sock_ptr->DetachService(this);
					sock_count_--;
					sock_ptrs_[i] = NULL;
					return i;
				} else {
					return i;
				}
				break;
			}
		}
		return -1;
	}

	int RemoveInvalidSocket(Socket* & sock_ptr)
	{
		//std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i]) {
				std::unique_lock<std::mutex> lock(mutex_);
				TSocket* t_sock_ptr = sock_ptrs_[i];
				if (t_sock_ptr) {
					if (!sock_ptrs_[i]->IsSocket()) {
						sock_ptr = sock_ptrs_[i];
						sock_ptr->DetachService(this);
						sock_count_--;
						sock_ptrs_[i] = NULL;
						return i;
						break;
					}
				}
			}
		}
		return -1;
	}

	void RemoveAllSocket(bool bClose = false)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if (sock_ptrs_[i]) {
				TSocket* sock_ptr = sock_ptrs_[i];
				if (sock_ptr->IsSocket()) {
					if (bClose) {
						sock_ptr->Close();
					}
				}
				sock_ptr->DetachService(this);
				sock_ptrs_[i] = NULL;
			}
		}
		sock_count_ = 0;
	}

protected:
	//
	virtual void OnIdle(int nErrorCode)
	{
		//std::unique_lock<std::mutex> lock(mutex_);
		int next = sock_idle_next_, next_end = sock_idle_next_ + 20;
		sock_idle_next_ = next_end % uFD_SETSize;
		for (; next < next_end; next++)
		{
			int i = next % uFD_SETSize;
			if (sock_ptrs_[i]) {
				std::unique_lock<std::mutex> lock(mutex_);
				TSocket* sock_ptr = sock_ptrs_[i];
				if (sock_ptr) {
					if (!sock_ptr->IsSocket()) {
						//
					} else if(sock_ptr->IsSelect(FD_IDLE)) {
						sock_ptr->Trigger(FD_IDLE, Tick());
					}
				}
			}
		}
	}
};

/*!
 *	@brief SocketManager 模板定义.
 *
 *	封装SocketManager，实现对管理多个SocketSet，可以支持任意数Socket
 */
template<class TSocketSet>
class SocketManager
{
public:
	typedef TSocketSet SocketSet;
	typedef typename TSocketSet::Socket Socket;
protected:
	std::vector<SocketSet*> sockset_ptrs_;
	size_t sockset_add_next_ = 0;
public:
	SocketManager(int nMaxSockSetCount)
	{
		sockset_ptrs_.resize(nMaxSockSetCount,NULL);
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i] = new SocketSet();
		}
		sockset_add_next_ = 0;
	}

	~SocketManager() 
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
	}

	void Stop()
	{
		for (size_t i = 0; i < sockset_ptrs_.size(); i++)
		{
			sockset_ptrs_[i]->Stop();
		}
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

	int AddSocket(Socket* sock_ptr, int evt = 0)
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

	int RemoveSocket(Socket* sock_ptr)
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

	int RemoveInvalidSocket(Socket* & sock_ptr)
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
	}

protected:
};

/*!
 *	@brief SelectSocket 模板定义.
 *
 *	封装SelectSocket，实现对select模型管理一个客户端连接Socket
 */
template<class TService = ThreadService, class TBase = SocketEx>
class SelectSocket : public TBase, public TService
{
	typedef SelectSocket<TService,TBase> This;
	typedef TBase Base;
public:
	typedef TService Service;
public:
	SelectSocket() : Base()
	{
    	
	}

protected:
	//
	virtual void OnIdle(int nErrorCode)
	{
		
	}

	virtual void OnRunOnce()
	{
		Service::OnRunOnce();

		if(!Base::IsSocket()) {
			return;
		}

		int fd = *this;
		int nfds = 0;
		int maxfds = 0;
		fd_set exceptfds;
		FD_ZERO(&exceptfds);
		maxfds = fd + 1;
		FD_SET(fd, &exceptfds);
		struct timeval tv = {0, 0};
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
			}
		} else if (Base::IsSelect(FD_CONNECT)) {
			fd_set writefds;
			FD_ZERO(&writefds);
			maxfds = fd + 1;
			FD_SET(fd, &writefds);
			nfds = select(maxfds, NULL, &writefds, &exceptfds, &tv);
			if (nfds > 0) {
				if (FD_ISSET(fd, &writefds)) {
					int nErrorCode = 0;
					Base::GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
					Base::Trigger(FD_CONNECT, nErrorCode);
					Base::RemoveSelect(FD_CONNECT);
					if (Base::IsSocket() && Base::IsSelect(FD_WRITE)) {
						Base::Trigger(FD_WRITE, 0);
					}
					if (Base::IsSocket() && Base::IsSelect(FD_READ)) {
						Base::Trigger(FD_READ, 0);
					}
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
			}
		}
		if (nfds > 0) {
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
				Base::Trigger(FD_CLOSE, nErrorCode);
			}
		} else if (nfds == 0) {
			//
		} else {
			if (Base::IsSocket()) {
				Base::Trigger(FD_CLOSE, GetLastError());
			}
		}
	}
};

/*!
 *	@brief SelectSocketSet 模板定义.
 *
 *	封装SelectSocketSet，实现对select模型封装，最多管理uFD_SETSize数Socket
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
class SelectSocketSet : public SocketSet<TService,TSocket,uFD_SETSize>
{
	typedef SocketSet<TService,TSocket,uFD_SETSize> Base;
public:
	typedef TService Service;
	typedef TSocket Socket;
public:
	SelectSocketSet()
	{
		
	}

protected:
	//
	virtual void OnRunOnce()
	{
		Base::OnRunOnce();
		
		int nfds = 0;
		int maxfds = 0;
		fd_set exceptfds;
		FD_ZERO(&exceptfds);
		fd_set readfds;
		FD_ZERO(&readfds);
		fd_set writefds;
		FD_ZERO(&writefds);
		struct timeval tv = {0, 0};
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
		if (nfds > 0) {
			for (size_t i = 0; i < uFD_SETSize; ++i)
			{
				if (Base::sock_ptrs_[i]) {
					lock.lock();
					Socket *sock_ptr = Base::sock_ptrs_[i];
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
								int nErrorCode = 0;
								sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, &nErrorCode, sizeof(nErrorCode));
								sock_ptr->Trigger(FD_CONNECT, nErrorCode);
								sock_ptr->RemoveSelect(FD_CONNECT);
								if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_WRITE)) {
									sock_ptr->Trigger(FD_WRITE, 0);
								}
								if (sock_ptr->IsSocket() && sock_ptr->IsSelect(FD_READ)) {
									sock_ptr->Trigger(FD_READ, 0);
								}
							} else {
								sock_ptr->Trigger(FD_WRITE, 0);
							}
						}
						if (FD_ISSET(*sock_ptr, &exceptfds)) {
							int nErrorCode = sock_ptr->GetLastError();
							sock_ptr->GetSockOpt(SOL_SOCKET, SO_ERROR, (char *)&nErrorCode, sizeof(nErrorCode));
							if (nErrorCode == 0) {
								nErrorCode = ENETDOWN;
							}
							sock_ptr->SetLastError(nErrorCode);
							sock_ptr->Trigger(FD_CLOSE, nErrorCode);
						}
					}
					lock.unlock();
				}
			}
		} else if (nfds == 0) {
			//
		} else {
			//
		}
	}
};

/*!
 *	@brief SelectManager 模板定义.
 *
 *	封装SelectManager，实现对select模型管理监听Socket连接，依赖SelectSocket
 */
template<class T, class TService, class TBase = ListenSocket<SocketEx>, class TWorkSocket = WorkSocket<SocketEx>>
class SelectListen : public SelectSocket<TService,TBase>
{
	typedef SelectSocket<TService,TBase> Base;
public:
	typedef TService Service;
	typedef TWorkSocket SockWorker;
protected:
	std::vector<SockWorker*> sock_ptrs_;
public:
	SelectListen() : Base()
	{
		
	}

	inline const char* GetAddress() { return nullptr; }
	inline u_short GetPort() { return 0; }

protected:
	//
	virtual bool OnInit()
	{
		T* pT = static_cast<T*>(this);
		//服务初始化，获取配置信息，启动服务
		sock_ptrs_.reserve(pT->GetMaxSocketCount());
		const char* addr = pT->GetAddress();
		u_short port = pT->GetPort();
		if(port != 0) {
			pT->Open();
			pT->Bind(addr, port);
			pT->Listen();
			return true;
		}

		return false;
	}

	virtual void OnTerm()
	{
		T* pT = static_cast<T*>(this);
		//服务结束运行，释放资源
		if(pT->IsSocket()) {
#ifndef WIN32
			pT->ShutDown();
#endif
			pT->Close();
		}
		pT->RemoveAllSocket(true);
		for (size_t i = 0; i < sock_ptrs_.size(); i++)
		{
			DeletePeer(sock_ptrs_[i]);
		}
		sock_ptrs_.clear();
	}

	virtual SockWorker* NewPeer()
	{
		return new SockWorker();
	}

	virtual void DeletePeer(SockWorker* sock_ptr)
	{
		delete sock_ptr;
	}

	virtual void OnAddPeer(SockWorker* sock_ptr)
	{
		sock_ptrs_.push_back(sock_ptr);
	}

	virtual void OnRemovePeer(SockWorker* sock_ptr)
	{
		sock_ptrs_.erase(std::find(sock_ptrs_.begin(),sock_ptrs_.end(),sock_ptr));
	}

protected:
	//
	virtual void OnIdle(int nErrorCode)
	{
		Base::OnIdle(nErrorCode);

		T* pT = static_cast<T*>(this);
		SockWorker* sock_ptr = NULL;
		if (pT->RemoveInvalidSocket(sock_ptr) >= 0) {
			OnRemovePeer(sock_ptr);
			DeletePeer(sock_ptr);
		}
	}

	virtual void OnAccept(int nErrorCode)
	{
		if(nErrorCode) {
			return Base::OnAccept(nErrorCode);
		}

		T* pT = static_cast<T*>(this);
		//bool bConitnue = false;
		//do {
		//	bConitnue = false;
			SOCKADDR_IN Addr = {0};
			int AddrLen = sizeof(SOCKADDR_IN);
			SOCKET Sock = Base::Accept((SOCKADDR*)&Addr, &AddrLen);
	 		if(XSocket::IsSocket(Sock)) {
				Base::Trigger(FD_ACCEPT, (const char*)&Addr, AddrLen, (int)Sock);
				//bConitnue = true;
			} else {
				nErrorCode = GetLastError();
				switch(nErrorCode)
				{
				case EWOULDBLOCK:
					break;
	#ifdef WIN32
				case WSA_IO_PENDING:
					break;
	#else
				case EINTR:
					//bConitnue = true;
					break;
	#endif//
				default:
					Base::Trigger(FD_CLOSE,nErrorCode);
					break;
				}
			}
		//} while (bConitnue);
	}

	virtual void OnAccept(const SOCKADDR* lpSockAddr, int nSockAddrLen, SOCKET Sock) 
	{
		T* pT = static_cast<T*>(this);
				//测试下还能不能再接收SOCKET
				if(pT->AddSocket(NULL) < 0) {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.\n");
					XSocket::Close(Sock);
					return;
				}
				SockWorker* sock_ptr = NewPeer();
				sock_ptr->Attach(Sock,SOCKET_ROLE_WORK);
				
	#ifdef WIN32
				sock_ptr->IOCtl(FIONBIO, 1);//设为非阻塞模式
	#else
				int flags = sock_ptr->IOCtl(F_GETFL,(u_long)0); 
				sock_ptr->IOCtl(F_SETFL, (u_long)(flags|O_NONBLOCK)); //设为非阻塞模式
				//sock_ptr->IOCtl(F_SETFL, (u_long)(flags&~O_NONBLOCK)); //设为阻塞模式
	#endif//
				int pos = pT->AddSocket(sock_ptr, FD_READ|FD_WRITE|FD_OOB);
				if(pos >= 0) {
					OnAddPeer(sock_ptr);
				} else {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.\n");
					sock_ptr->Close();
					DeletePeer(sock_ptr);
				}
	}
};

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief SelectClient 模板定义.
 *
 *	封装SelectClient，实现对select模型管理一个客户端Tcp Socket
 */
template<class TService = ThreadService, class TBase = ConnectSocket<SocketEx>> 
class SelectClient : public SelectSocket<TService,TBase>
{
	typedef SelectSocket<TService,TBase> Base;
public:
	SelectClient():Base()
	{
		
	}
	virtual ~SelectClient()
	{
		Base::Stop();
	}

protected:
};


/*!
 *	@brief SelectServer 模板定义.
 *
 *	封装SelectServer，实现对select模型管理监听Socket连接，依赖SelectSet/SelectManager
 */
template<class T, class TService, class TBase, class TSocketSet>
class SelectServer 
: public SelectListen<T,TService,TBase,typename TSocketSet::Socket>
, public SocketManager<TSocketSet>
{
public:
	typedef TSocketSet SocketSet;
	typedef typename SocketSet::Socket Socket;
	typedef SocketManager<SocketSet> SockManager;
	typedef SelectListen<T,TService,TBase,Socket> Base;
public:
	SelectServer(int nMaxSocketCount) : Base(),SockManager((nMaxSocketCount+SocketSet::GetMaxSocketCount()-1)/SocketSet::GetMaxSocketCount())
	{
		
	}

	~SelectServer()
	{
		Stop();
	}

	bool Start()
	{
		Base::Start();
		SockManager::Start();
	}

	void Stop()
	{
		SockManager::Stop();
		Base::Stop();
	}
};

/*!
 *	@brief SelectUdpClient 模板定义.
 *
 *	封装SelectUdpClient，实现对select模型管理一个客户端Udp Socket
 */
template<class TService = ThreadService, class TBase = SocketEx> 
class SelectUdpClient : public SelectSocket<TService,TBase>
{
	typedef SelectSocket<TService,TBase> Base;
public:
	SelectUdpClient():Base()
	{

	}
	virtual ~SelectUdpClient()
	{
		Base::Stop();
	}

protected:
};

/*!
 *	@brief SelectUdpServer 模板定义.
 *
 *	封装SelectUdpServer，实现对select模型管理一个服务端Udp Socket
 */
template<class TService = ThreadService, class TBase = SocketEx>
class SelectUdpServer : public SelectSocket<TService,TBase>
{
	typedef SelectSocket<TService,TBase> Base;
public:
	SelectUdpServer():Base()
	{

	}
	virtual ~SelectUdpServer()
	{
		Base::Stop();
	}

protected:
};

}

#endif//_H_XSOCKETEX_H_
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
		if(evt == FD_IDLE) {
			OnIdle(nErrorCode);
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
		// 	OnIdle(nErrorCode);
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
	virtual void OnAttachService(Service* pSvr);
	virtual void OnDetachService(Service* pSvr);

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
	virtual void OnAccept(const SOCKADDR* lpSockAddr, int nSockAddrLen, SOCKET Sock);

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

	template <class Ty>
	class QueueT
	{
	public:
		QueueT() { }
		QueueT(const QueueT<Ty>&) = delete;
		QueueT& operator=(const QueueT<Ty>&) = delete;
		~QueueT() { 
#ifdef _DEBUG
			//std::lock_guard<std::mutex> lock(mutex_);
			if(!queue_.empty()) {
				PRINTF("Queue is not empty, size=%u\n", queue_.size());
			}
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

	inline void RemoveSocket(SocketEx* sock_ptr) {}

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
 *	@brief EventService 定义.
 *
 *	封装EventService，实现事件服务框架
 */
template<class TEvent, class TBase = Service>
class EventServiceT : public TBase
{
	typedef TBase Base;
public:
	typedef TEvent Event;
protected:
	//Queue<Event> queue_;
	std::vector<Event> queue_;
	std::mutex mutex_;
	//std::condition_variable cv_;
public:
	EventServiceT()
	{
		queue_.reserve(1024);
	}

	inline void Post(const Event& evt) {
		std::lock_guard<std::mutex> lock(mutex_);
		queue_.emplace_back(evt);
	}

protected:
	//
	inline void RemoveSocket(SocketEx* sock_ptr) {
		std::unique_lock<std::mutex> lock(mutex_);
		for(int i = queue_.size() - 1; i >= 0; i--)
		{
			const Event& evt = queue_[i];
			if (IsSocketEvent(sock_ptr, evt)) {
				queue_.erase(queue_.begin() + i);
			}
		}
	}
	inline bool IsSocketEvent(SocketEx* sock_ptr, const Event& evt) {
		return false;
	}

	inline bool Pop(Event& evt) {
		std::unique_lock<std::mutex> lock(mutex_);
		if (!queue_.empty()) {
			evt = queue_[0];
			queue_.erase(queue_.begin());
			return true;
		}
		return false;
	}

	virtual void OnEvent(const Event& evt)
	{
		
	}

	virtual void OnRunOnce()
	{
		for(size_t i = 0, j = queue_.size(); i < j; i++)
		{
			Event evt;
			if (Pop(evt)) {
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
class DealyEventT : public TEvent
{
	typedef DealyEventT<TEvent> This;
	typedef TEvent Base;
public:
	typedef TEvent Event;
public:
	DealyEventT():Base(){}
	DealyEventT(Event evt):Base(evt){}
	DealyEventT(Event evt, size_t _delay, size_t _repeat):Base(evt),time(std::chrono::steady_clock::now()),delay(_delay),repeat(_repeat){}
	DealyEventT(const This& o):Base((Event)o),time(o.time),delay(o.delay),repeat(o.repeat){}
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
class DelayEventServiceT : public EventServiceT<DealyEventT<TEvent>,TBase>
{
	typedef EventServiceT<DealyEventT<TEvent>,TBase> Base;
public:
	typedef TEvent Event;
	typedef DealyEventT<TEvent> DelayEvent;
public:
	
	inline void Post(const Event& evt) {
		PostDelay(evt);
	}

	inline void PostDelay(const Event& evt, size_t mills = 0, size_t repeat = 0) {
		if(mills) {
			Base::Post(DelayEvent(evt,mills,repeat));
		} else {
			Base::Post(DelayEvent(evt));
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
			if (Base::Pop(evt)) {
				if(evt.IsPoint()) {
					OnEvent(evt);
					evt.Update();
					if(evt.IsRepeat()) {
						Base::Post(evt);
					}
				} else {
					Base::Post(evt);
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
	bool m_bConnected;
	unsigned long m_ConnectTime;
	unsigned long m_ConnectTimeOut;

public:
	ConnectSocketT():Base(), m_bConnected(false), m_ConnectTime(0), m_ConnectTimeOut(0) {}
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
 *	@brief ListenSocketT 模板定义.
 *
 *	封装ListenSocket，适用于服务端监听Socket
 */
template<class TBase = SocketEx>
class ListenSocketT : public TBase
{
	typedef TBase Base;
public:
	ListenSocketT():Base()
	{

	}

protected:
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
public:
	typedef TService Service;
	typedef TSocket Socket;
	//static const u_short SOCKET_SETSIZE = uFD_SETSize;
protected:
	u_short sock_count_;
	std::shared_ptr<Socket> sock_ptrs_[uFD_SETSize];
	u_short sock_idle_next_;
	std::mutex mutex_;
public:
	SocketSetT()
	{
		sock_count_ = 0;
		//memset(sock_ptrs_,0,sizeof(sock_ptrs_));
		sock_idle_next_ = 0;
	}

	void Stop()
	{
		Service::Stop();
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
		if(!sock_ptr) {
			return false;
		}
		int i;
		for (i=0;i<uFD_SETSize;i++)
		{
			if(sock_ptrs_[i].get()==sock_ptr) {
				return sock_ptrs_[i];
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

	virtual void OnIdle(int nErrorCode)
	{
		int next = sock_idle_next_, next_end = sock_idle_next_ + 20;
		sock_idle_next_ = next_end % uFD_SETSize;
		for (; next < next_end; next++)
		{
			int i = next % uFD_SETSize;
			if (sock_ptrs_[i]) {
				std::shared_ptr<Socket> sock_ptr = sock_ptrs_[i];
				if (sock_ptr) {
					if (!sock_ptr->IsSocket()) {
						if(!sock_ptr->IsSelect(-1)) { 
							//自动移除
							RemoveSocketByPos(i);
						}
					} else if(sock_ptr->IsSelect(FD_IDLE)) {
						sock_ptr->RemoveSelect(FD_IDLE);
						sock_ptr->Trigger(FD_IDLE, Tick());
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

	int AddSocket(std::shared_ptr<Socket> sock_ptr, int evt = 0)
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

	int RemoveSocket(std::shared_ptr<Socket> sock_ptr)
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
 *	@brief SelectSvrSocket 模板定义.
 *
 *	封装SelectSvrSocket，实现对select模型管理一个客户端连接Socket
 */
template<class TService = ThreadService, class TBase = SocketEx>
class SelectOneSocketT : public TBase, public TService
{
	typedef SelectOneSocketT<TService,TBase> This;
	typedef TBase Base;
public:
	typedef TService Service;
public:
	SelectOneSocketT() : Base()
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
 *	封装SelectSocket，实现对select模型管理一个客户端连接Socket
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
};

/*!
 *	@brief SelectSocketSet 模板定义.
 *
 *	封装SelectSocketSet，实现对select模型封装，最多管理uFD_SETSize数Socket
 */
template<class TService = ThreadService, class TSocket = SocketEx, u_short uFD_SETSize = FD_SETSIZE>
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

/*!
 *	@brief SelectManager 模板定义.
 *
 *	封装SelectManager，实现对select模型管理监听Socket连接，依赖SelectSocket
 */
template<class TService, class TBase = ListenSocketT<SocketEx>>
class SelectListenT : public SelectOneSocketT<TService,TBase>
{
	typedef SelectOneSocketT<TService,TBase> Base;
public:
	typedef TService Service;
	std::string address_;
	u_short port_;
public:
	SelectListenT() : Base()
	{
		
	}

	bool Start(const char* address, u_short port)
	{
		address_ = address;
		port_ = port;
		return Base::Start();
	}

protected:
	//
	virtual bool OnInit()
	{
		if(port_ <= 0) {
			return false;
		}
		Base::Open();
		Base::SetSockOpt(SOL_SOCKET, SO_REUSEADDR, 1);
		Base::Bind(address_.c_str(), port_);
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
: public SelectListenT<TService,TBase>
, public SocketManagerT<TSocketSet>
{
public:
	typedef TSocketSet SocketSet;
	typedef typename SocketSet::Socket Socket;
	typedef SocketManagerT<SocketSet> SockManager;
	typedef SelectListenT<TService,TBase> Base;
public:
	SelectServerT(int nMaxSocketCount) : Base(),SockManager((nMaxSocketCount+SocketSet::GetMaxSocketCount()-1)/SocketSet::GetMaxSocketCount())
	{
		
	}

	~SelectServerT()
	{
		
	}

	bool Start(const char* address, u_short port)
	{
		if(!Base::Start(address, port)) {
			return false;
		}
		if(!SockManager::Start()) {
			return false;
		}
		return true;
	}

	void Stop()
	{
		SockManager::Stop();
		Base::Stop();
	}

protected:
	//
	virtual void OnAccept(const SOCKADDR* lpSockAddr, int nSockAddrLen, SOCKET Sock) 
	{
				//测试下还能不能再接收SOCKET
				if(SockManager::AddSocket(NULL) < 0) {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.\n");
					XSocket::Close(Sock);
					return;
				}
				std::shared_ptr<Socket> sock_ptr = std::make_shared<Socket>();
				sock_ptr->Attach(Sock,SOCKET_ROLE_WORK);
				
	#ifdef WIN32
				sock_ptr->IOCtl(FIONBIO, 1);//设为非阻塞模式
	#else
				int flags = sock_ptr->IOCtl(F_GETFL,(u_long)0); 
				sock_ptr->IOCtl(F_SETFL, (u_long)(flags|O_NONBLOCK)); //设为非阻塞模式
				//sock_ptr->IOCtl(F_SETFL, (u_long)(flags&~O_NONBLOCK)); //设为阻塞模式
	#endif//
				int pos = SockManager::AddSocket(sock_ptr, FD_READ|FD_WRITE|FD_OOB);
				if(pos >= 0) {
					//
				} else {
					PRINTF("The connection was refused by the computer running select server because the maximum number of sessions has been exceeded.\n");
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
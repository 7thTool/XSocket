// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XProxySocketEx.h"
#include "../../../XSocket/XSocketImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//

class worker;

class Event
{
public:
	worker* dst = nullptr;
	int id;
	std::string buf;
	int flags;

	Event() {}
	Event(worker* d, int id, const char* buf, int len, int flag):dst(d),id(id),buf(buf,len),flags(flag){}

	// inline int get_id() { return evt; }
	// inline const char* get_data() { return data.c_str(); }
	// inline int get_datalen() { return data.size(); }
	// inline int get_flags() { return flags; }
};
typedef XSocket::SampleEventService<XSocket::DelayEventService<Event,XSocket::ThreadService>> WorkService;
//typedef XSocket::ThreadService WorkService;

#ifndef USE_UDP
#ifdef USE_EPOLL
typedef XSocket::EPollSocketSet<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#elif defined(USE_IOCP)
typedef XSocket::CompletionPortSocketSet<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#else
typedef XSocket::SelectSocketSet<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#endif//
#endif//USE_UDP

#ifndef USE_UDP
class worker
#ifdef USE_EPOLL
	: public XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::EPollSocket<XSocket::SocketEx>>>
#elif defined(USE_IOCP)
	: public XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::CompletionPortSocket<XSocket::SocketEx>>>
#else
	: public XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::SocketEx>>
#endif
{
#ifdef USE_EPOLL
	typedef XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::EPollSocket<XSocket::SocketEx>>> Base;
#elif defined(USE_IOCP)
	typedef XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::CompletionPortSocket<XSocket::SocketEx>>> Base;
#else
	typedef XSocket::SampleEvtSocketImpl<WorkSocketSet,XSocket::WorkSocket<XSocket::SocketEx>> Base;
#endif
protected:
	
public:
	worker()
	{
		
	}

	~worker() 
	{
		
	}

public:
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}

	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.flags);
		}
	}
protected:
	//
	virtual void OnIdle(int nErrorCode)
	{
		/*char lpBuf[DEFAULT_BUFSIZE+1];
		int nBufLen = 0;
		int nFlags = 0;
		nBufLen = Receive(lpBuf,DEFAULT_BUFSIZE,&nFlags);
		if (nBufLen<=0) {
			return;
		}
		lpBuf[nBufLen] = 0;
		PRINTF("%s\n", lpBuf);
		PRINTF("echo:%s\n", lpBuf);
		Send(lpBuf,nBufLen);*/
	}

	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags)
	{
		PostBuf(lpBuf,nBufLen,0);
		Base::OnRecvBuf(lpBuf,nBufLen,nFlags);
	}

};

class server 
#ifdef USE_EPOLL
	: public XSocket::EPollServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet>
#elif defined(USE_IOCP)
	: public XSocket::CompletionPortServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet>
#else
	: public XSocket::SelectServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet>
#endif//
{
#ifdef USE_EPOLL
	typedef XSocket::EPollServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet> Base;
#elif defined(USE_IOCP)
	typedef XSocket::CompletionPortServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet> Base;
#else
	typedef XSocket::SelectServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,WorkSocketSet> Base;
#endif//
public:
	server(int nMaxSocketCount = DEFAULT_MAX_FD_SETSIZE):Base(nMaxSocketCount)
	{

	}

	inline int GetMaxSocketCount() { return DEFAULT_MAX_FD_SETSIZE; }
	inline const char* GetAddress() { return DEFAULT_IP; }
	inline u_short GetPort() { return DEFAULT_PORT; }

	bool OnChar(char c)
	{
		switch(c)
		{
		case 'x':
		case 'X':
			printf("server worker count is [%d]\n", GetSocketCount());
			break;
		case 'q':
		case 'Q':
			return false;
			break;
		}
		return true;
	}
};

#else
class server : public SocketExImpl<server,SelectUdpServer<SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<SocketEx> > > >
{
	typedef SocketExImpl<server,SelectUdpServer<SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<SocketEx> > > > Base;
public:

protected:
	//
	virtual void OnIdle(int nErrorCode)
	{
		Base::OnIdle(nErrorCode);
	
		char lpBuf[DEFAULT_BUFSIZE+1];
		int nBufLen = 0;
		SOCKADDR_IN SockAddr = {0};
		int nFlags = 0;
		nBufLen = Receive(lpBuf,DEFAULT_BUFSIZE,&SockAddr,&nFlags);
		if (nBufLen<=0) {
			return;
		}
		lpBuf[nBufLen] = 0;
		PRINTF("%s\n", lpBuf);
		PRINTF("echo[(%s:%d)]:%s\n",N2Ip(SockAddr.sin_addr.s_addr),N2H(SockAddr.sin_port),lpBuf);
		Send(lpBuf,nBufLen,SockAddr);
	}
};
#endif//USE_UDP

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	XSocket::InitNetEnv();

	server *s = new server();
	s->Start();
	getchar();
	s->Stop();
	delete s;

	XSocket::ReleaseNetEnv();

	return 0;
}


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
#ifdef USE_EPOLL
typedef XSocket::EPollSocketSet<XSocket::ThreadService,worker,DEFAULT_FD_SETSIZE> ServerSocketSet;
#elif defined(USE_IOCP)
typedef XSocket::CompletionPortSocketSet<XSocket::ThreadService,worker,DEFAULT_FD_SETSIZE> ServerSocketSet;
#endif//

#ifndef USE_UDP
class worker
#ifdef USE_EPOLL
	: public XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::EPollSocket<ServerSocketSet,XSocket::SocketEx>>>>
#elif defined(USE_IOCP)
	: public XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::CompletionPortSocket<ServerSocketSet,XSocket::SocketEx>>>>
#else
	: public XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::SocketEx>>>
#endif
{
#ifdef USE_EPOLL
	typedef XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::EPollSocket<ServerSocketSet,XSocket::SocketEx>>>> Base;
#elif defined(USE_IOCP)
	typedef XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::CompletionPortSocket<ServerSocketSet,XSocket::SocketEx>>>> Base;
#else
	typedef XSocket::SampleSocketImpl<XSocket::SocketWrapper<XSocket::WorkSocket<XSocket::SocketEx>>> Base;
#endif
protected:
	
public:
	worker()
	{
		
	}

	~worker() 
	{
		
	}

protected:
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
		SendBuf(lpBuf,nBufLen,0);
	}

};

class server 
#ifdef USE_EPOLL
	: public XSocket::EPollServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,ServerSocketSet>
#elif defined(USE_IOCP)
	: public XSocket::CompletionPortServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,ServerSocketSet>
#else
	: public XSocket::SelectServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,worker,DEFAULT_FD_SETSIZE>
#endif//
{
#ifdef USE_EPOLL
	typedef XSocket::EPollServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,ServerSocketSet> Base;
#elif defined(USE_IOCP)
	typedef XSocket::CompletionPortServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,ServerSocketSet> Base;
#else
	typedef XSocket::SelectServer<server,XSocket::ThreadService,XSocket::ListenSocket<XSocket::SocketEx>,worker,DEFAULT_FD_SETSIZE> Base;
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


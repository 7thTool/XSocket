// Multicast.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../samples.h"
#include "../../XProxySocketEx.h"
#include "../../XSocketArchitecture.h"
#ifdef WIN32
#include <WS2tcpip.h>
#else

#endif//



class peer
#ifndef USE_MANAGER
	: public SocketExImpl<peer,SelectUdpClient<SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<ConnectSocket<SocketEx>,SockAddrType >,SockAddrType > > >
#else
	: public SocketExImpl<peer,SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<ConnectSocket<SocketEx>,SockAddrType >,SockAddrType > >
#endif//USE_MANAGER
{
#ifndef USE_MANAGER
	typedef SocketExImpl<peer,SelectUdpClient<SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<ConnectSocket<SocketEx>,SOCKADDR_IN6 >,SOCKADDR_IN6 > > > Base;
#else
	typedef SocketExImpl<peer,SampleUdpSocketArchitectureImpl<SampleUdpSocketArchitecture<ConnectSocket<SocketEx>,SockAddrType >,SockAddrType > > Base;
#endif//USE_MANAGER

#ifdef USE_MANAGER
	friend class SelectSet<peer,DEFAULT_FD_SETSIZE>;
	friend class SelectManager<peer,DEFAULT_FD_SETSIZE>;
#endif//USE_MANAGER

protected:
	int m_incr;
public:
	peer():m_incr(0)
	{
#if USE_SOCKET_THREADPOOL
		m_WorkThread = RegisterThreadPool(WorkThread, (void*)this);
#else
		m_WorkThread.CreateThread(WorkThread, (void*)this);
#endif//
	}

	~peer()
	{
#if USE_SOCKET_THREADPOOL
		UnRegisterThreadPool(m_WorkThread);
		m_WorkThread = 0;
#else
		m_WorkThread.StopThread();
#endif//
	}

protected:
	int OnWork()
	{
		if (m_incr==0) {
			Thread::Sleep(3000);

			char lpBuf[DEFAULT_BUFSIZE+1];
			int nBufLen = 0;
			nBufLen = sprintf(lpBuf,"%d", ++m_incr);
			SockAddrType SockAddr = {0};
#ifdef USE_IPV6
			ADDRINFO hints = {0};
			hints.ai_family = PF_INET6;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			hints.ai_flags = AI_NUMERICHOST;
			ADDRINFO* res = NULL;
			getaddrinfo(DEFAULT_MULTICAST_IP, DEFAULT_MULTICAST_PORTS, &hints, &res);
			memcpy(&SockAddr, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
			res = NULL;
			Send(lpBuf, nBufLen, SockAddr, 0);
			PRINTF("say:%s\n", lpBuf);
#else
			SockAddr.sin_family = AF_INET;
			SockAddr.sin_addr.s_addr = inet_addr(DEFAULT_MULTICAST_IP);
			SockAddr.sin_port = H2N((u_short)DEFAULT_MULTICAST_PORT);
			Send(lpBuf, nBufLen, SockAddr, 0);
			PRINTF("say:%s\n", lpBuf);
#endif//
		}
		
		return 0;
	}
	//
	virtual void OnIdle(int nErrorCode)
	{
		Base::OnIdle(nErrorCode);

		char lpBuf[DEFAULT_BUFSIZE+1];
		int nBufLen = 0;
		SockAddrType SockAddr = {0};
		int nFlags = 0;
		nBufLen = Receive(lpBuf,DEFAULT_BUFSIZE,&SockAddr,&nFlags);
		if (nBufLen<=0) {
			return;
		}
		lpBuf[nBufLen] = 0;
		PRINTF("%s\n", lpBuf);
		//nBufLen = sprintf(lpBuf,"%d", ++m_incr);
		//Send(lpBuf,nBufLen,SOCKET_PACKET_FLAG_TEMPBUF);
		//PRINTF("say:%s\n", lpBuf);
	}

protected:
#if USE_SOCKET_THREADPOOL
	long m_WorkThread;
	static unsigned int __stdcall WorkThread(void* pParam)
	{
		peer* pThis = (peer*)pParam;
		ASSERT(pThis);
		return pThis->OnWork();
		return 0;
	}
#else
	Thread m_WorkThread;
	static unsigned int __stdcall WorkThread(void* pParam)
	{
		peer* pThis = (peer*)pParam;
		ASSERT(pThis);
		while (!pThis->m_WorkThread.IsNeedStop())
		{
			pThis->OnWork();
		}
		return 0;
	}
#endif//
};

void run()
{
#ifdef USE_MANAGER
	SelectManager<peer,DEFAULT_FD_SETSIZE> m(DEFAULT_CLIENT_COUNT);
#endif//

	int i;
	peer *c = new peer[DEFAULT_CLIENT_COUNT];
	for(i=0;i<DEFAULT_CLIENT_COUNT;i++)
	{
		int err = 0;
		char buf[DEFAULT_BUFSIZE] = {0};
#ifdef USE_IPV6
		c[i].Create(AF_INET6,SOCK_DGRAM);

		bool optval = true;
		err = c[i].SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));
		if( SOCKET_ERROR == err ) { 
			;
		}

		//设置多播跳数
		int routenum = 10;  
		err = c[i].SetSockOpt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&routenum,sizeof(routenum));
		if( err == SOCKET_ERROR )  
		{  
			;
		}

		bool loop = true;
		err = c[i].SetSockOpt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char FAR *)&loop, sizeof(loop));
		if( SOCKET_ERROR == err ) {  
			;
		}

		SockAddrType addr = {0};
		int addrlen = sizeof(SockAddrType);
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = c[i].H2N((u_short)DEFAULT_MULTICAST_PORT);
		err = c[i].Bind((SOCKADDR*)&addr, addrlen);
		if ( SOCKET_ERROR == err ) {
			c[i].GetErrorMessageA(c[i].GetLastError(),buf,DEFAULT_BUFSIZE);
			PRINTF("%s\n",buf);
		}

		struct ipv6_mreq mreq; 
		//err = inet_pton(AF_INET6,DEFAULT_MULTICAST_IPV6,&mreq.ipv6mr_multiaddr);
		err = WSAStringToAddressA(DEFAULT_MULTICAST_IP,AF_INET6,NULL,(LPSOCKADDR)&addr,&addrlen);
		mreq.ipv6mr_multiaddr = addr.sin6_addr;
		mreq.ipv6mr_interface = htonl(INADDR_ANY);
		err = c[i].SetSockOpt(IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));
		if( SOCKET_ERROR == err ) {
			;
		}
#else
		c[i].Create(AF_INET,SOCK_DGRAM);

		bool optval = true;
		err = c[i].SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));
		if( SOCKET_ERROR == err ) { 
			;
		}

		int ttl = 127;
		err = c[i].SetSockOpt(IPPROTO_IP, IP_MULTICAST_TTL, (char FAR *)&ttl, sizeof(ttl));
		if( SOCKET_ERROR == err ) { 
			;
		}

		bool loop = true;
		err = c[i].SetSockOpt(IPPROTO_IP, IP_MULTICAST_LOOP, (char FAR *)&loop, sizeof(loop));
		if( SOCKET_ERROR == err ) {  
			;
		}

		SockAddrType addr = {0};
		addr.sin_family=AF_INET;  
		addr.sin_addr.s_addr=c[i].H2N(INADDR_ANY);
		addr.sin_port=c[i].H2N((u_short)DEFAULT_MULTICAST_PORT);  
		err = c[i].Bind((SOCKADDR*)&addr, sizeof(SockAddrType));
		if ( SOCKET_ERROR == err ) {
			;
		}

		struct ip_mreq mreq; 
		mreq.imr_multiaddr.s_addr=inet_addr(DEFAULT_MULTICAST_IP);
		mreq.imr_interface.s_addr=htonl(INADDR_ANY); 
		err = c[i].SetSockOpt(IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));
		if( SOCKET_ERROR == err ) {
			;
		}
#endif//

#ifdef USE_MANAGER
		m.AddSocket(&c[i]);
#endif//
	}
	getchar();
#ifdef USE_MANAGER
	m.Clear(true);
#else
	for(i=0;i<DEFAULT_CLIENT_COUNT;i++)
	{
		if (c[i].IsSocket()) {
			c[i].Close();
		}
	}
#endif//
	delete []c;
}

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	XLibInit::Init();
	peer::InitNetEnv();

	run();

	peer::ReleaseNetEnv();
	XLibInit::Release();
	return 0;
}


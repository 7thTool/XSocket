#include "../../samples.h"
#include "../../../XSocket/XProxySocketEx.h"
#include "../../../XSocket/XSocketImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#endif//

class client;

class Event
{
public:
	client* dst = nullptr;
	int id;
	std::string buf;
	int flags;

	Event() {}
	Event(client* d, int id, const char* buf, int len, int flag):dst(d),id(id),buf(buf,len),flags(flag){}

	// inline int get_id() { return evt; }
	// inline const char* get_data() { return data.c_str(); }
	// inline int get_datalen() { return data.size(); }
	// inline int get_flags() { return flags; }
};
typedef XSocket::DelayEventServiceT<Event,XSocket::ThreadService> ClientService;

class client
#ifndef USE_UDP
#ifndef USE_MANAGER
	: public XSocket::SocketExImpl<client,XSocket::SelectClientT<ClientService,XSocket::SimpleSocketT<XSocket::ConnectSocketT<XSocket::SocketEx>>>>
#else
	: public SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > >
#endif//USE_MANAGER
#else
#ifndef USE_MANAGER
	: public SocketExT<client,SelectUdpClient<SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > >
#else
	: public SocketExT<client,SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > >
#endif//USE_MANAGER
#endif//USE_UDP
{
#ifndef USE_UDP
#ifndef USE_MANAGER
	typedef XSocket::SocketExImpl<client,XSocket::SelectClientT<ClientService,XSocket::SimpleSocketT<XSocket::ConnectSocketT<XSocket::SocketEx>>>> Base;
#else
	typedef SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > > Base;
#endif//USE_MANAGER
#else
#ifndef USE_MANAGER
	typedef SocketExT<client,SelectUdpClient<SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > > Base;
#else
	typedef SocketExT<client,SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > Base;
#endif//USE_MANAGER
#endif//USE_UDP
#ifdef USE_MANAGER
#ifdef USE_EPOLL
	friend class EPollManager<client,DEFAULT_FD_SETSIZE>;
#else
	friend class SelectSet<client,DEFAULT_FD_SETSIZE>;
	friend class SelectManager<client,DEFAULT_FD_SETSIZE>;
#endif//USE_EPOLL
#endif//USE_MANAGER
protected:
	//std::once_flag start_flag_;
	std::string addr_;
	u_short port_;
	int m_incr;
public:
	client():m_incr(0)
	{
		
	}

#ifndef USE_MANAGER
	bool Start(const std::string& addr, u_short port)
	{
		addr_ = addr;
		port_ = port;
		m_incr = 0;
		return Base::Start();
	}
protected:
	//
	bool OnInit()
	{
		if(!Base::OnInit()) {
			return false;
		}
	#ifndef USE_UDP
		Open();
	#else
		Open(AF_INET,SOCK_DGRAM);
	#endif//
		Connect(addr_.c_str(), port_);

		return true;
	}

	void OnTerm()
	{
		if (IsSocket()) {
			ShutDown();
			Close();
		}
		Base::OnTerm();
	}
#endif//USE_MANAGER

public:
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}

protected:
	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.flags);
		}
	}
	//
	/*virtual void OnIdle(int nErrorCode)
	{
		Base::OnIdle(nErrorCode);

		if (!IsConnected()) {
			return;
		}

		char lpBuf[DEFAULT_BUFSIZE+1];
		int nBufLen = 0;
		int nFlags = 0;
		nBufLen = Receive(lpBuf,DEFAULT_BUFSIZE,&nFlags);
		if (nBufLen<=0) {
			return;
		}
		lpBuf[nBufLen] = 0;
		PRINTF("%s\n", lpBuf);
		nBufLen = sprintf(lpBuf,"%d", ++m_incr);
		Send(lpBuf,nBufLen,SOCKET_PACKET_FLAG_TEMPBUF);
		PRINTF("say:%s\n", lpBuf);
	}*/

	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags)
	{
		Base::OnRecvBuf(lpBuf, nBufLen, nFlags);
		PRINTF("say:hello.\n");
		PostBuf("hello.",6,0);
	}

	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);
		if(!IsConnected()) {
			return;
		}
		PRINTF("say:hello.\n");
		SendBuf("hello.",6,0);
	}
};

#ifdef USE_MANAGER
#ifdef USE_EPOLL
class manager : public EPollManager<client,DEFAULT_FD_SETSIZE>
#else
class manager : public SelectManager<client,DEFAULT_FD_SETSIZE>
#endif//
#else
class manager : public XSocket::ThreadService
#endif//
{
protected:
	client *c;
public:

#ifdef USE_MANAGER
	manager(int nMaxSocketCount):Base(nMaxSocketCount)
#else
	manager(int nMaxSocketCount)
#endif
	{
		
	}
	~manager()
	{
		
	}

	virtual bool OnInit()
	{
		c = new client[DEFAULT_CLIENT_COUNT];
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
	#ifndef USE_MANAGER
			c[i].Start(DEFAULT_IP,DEFAULT_PORT);
	#else
	#ifndef USE_UDP
			c[i].Open();
	#else
			c[i].Open(AF_INET,SOCK_DGRAM);
	#endif//
			AddSocket(&c[i]);
			c[i].Connect(DEFAULT_IP,DEFAULT_PORT);
	#endif//
		}
		return true;
	}

	virtual void OnTerm()
	{
	#ifdef USE_MANAGER
		Base::OnTerm();
		RemoveAllSocket(true);
	#else
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Stop();
		}
	#endif//
		delete []c;
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	XSocket::InitNetEnv();
	
	manager m(DEFAULT_CLIENT_COUNT);
	m.Start();
	getchar();
	m.Stop();

	XSocket::ReleaseNetEnv();
	return 0;
}


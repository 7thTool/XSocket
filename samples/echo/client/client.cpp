#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#endif//
using namespace XSocket;

class client;

class Event
{
public:
	client* dst = nullptr;
	int id;
	std::string buf;
#ifdef USE_UDP
	SOCKADDR_IN addr;
#endif
	int flags;

	Event() {}
#ifndef USE_UDP
	Event(client* d, int id, const char* buf, int len, int flag):dst(d),id(id),buf(buf,len),flags(flag){}
#else
	Event(client* d, int id, const char* buf, int len, const SOCKADDR_IN& addr, int flag):dst(d),id(id),buf(buf,len),addr(addr),flags(flag){}
#endif

	// inline int get_id() { return evt; }
	// inline const char* get_data() { return data.c_str(); }
	// inline int get_datalen() { return data.size(); }
	// inline int get_flags() { return flags; }
};
typedef DelayEventServiceT<Event,ThreadService> ClientService;

class client
#ifndef USE_UDP
#ifndef USE_MANAGER
	: public SocketExImpl<client,SelectClientT<ClientService,SimpleSocketT<ConnectSocketT<SocketEx>>>>
#else
	: public SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > >
#endif//USE_MANAGER
#else
#ifndef USE_MANAGER
	: public SocketExImpl<client,SelectUdpClientT<ClientService,SimpleUdpSocketT<ConnectSocketT<SocketEx>>>>
#else
	: public SocketExT<client,SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > >
#endif//USE_MANAGER
#endif//USE_UDP
{
#ifndef USE_UDP
#ifndef USE_MANAGER
	typedef SocketExImpl<client,SelectClientT<ClientService,SimpleSocketT<ConnectSocketT<SocketEx>>>> Base;
#else
	typedef SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > > Base;
#endif//USE_MANAGER
#else
#ifndef USE_MANAGER
	typedef SocketExImpl<client,SelectUdpClientT<ClientService,SimpleUdpSocketT<ConnectSocketT<SocketEx>>>> Base;
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
		Connect(addr_.c_str(), port_);
	#else
		Open(AF_INET,SOCK_DGRAM);
		Select(FD_READ);
	#ifdef WIN32
		IOCtl(FIONBIO, 1);//设为非阻塞模式
	#else
		int flags = IOCtl(F_GETFL,(u_long)0); 
		IOCtl(F_SETFL, (u_long)(flags|O_NONBLOCK)); //设为非阻塞模式
		//IOCtl(F_SETFL, (u_long)(flags&~O_NONBLOCK)); //设为阻塞模式
	#endif//
		SOCKADDR_IN Addr = {0};
		Addr.sin_family = AF_INET;
		Addr.sin_addr.s_addr = Ip2N(Url2Ip(addr_.c_str()));
		Addr.sin_port = H2N((u_short)port_);
		PostBuf("hello.",6,Addr,SOCKET_PACKET_FLAG_TEMPBUF);
	#endif//
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
#ifndef USE_UDP
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}
#else
	inline void PostBuf(const char* lpBuf, int nBufLen, const SOCKADDR_IN& addr, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,addr,nFlags));
	}
#endif

protected:
	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
#ifndef USE_UDP
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.flags);
#else
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.addr,evt.flags);
#endif
		}
	}
	
#ifndef USE_UDP
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
#else
	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr)
	{
		PRINTF("say:hello.\n");
		PostBuf("hello.",6,SockAddr,SOCKET_PACKET_FLAG_TEMPBUF);
		Base::OnRecvBuf(lpBuf, nBufLen, SockAddr);
	}
#endif//
};

#ifdef USE_MANAGER
#ifdef USE_EPOLL
class manager : public EPollManager<client,DEFAULT_FD_SETSIZE>
#else
class manager : public SelectManager<client,DEFAULT_FD_SETSIZE>
#endif//
#else
class manager : public ThreadService
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
	Socket::Init();
	
	manager m(DEFAULT_CLIENT_COUNT);
	m.Start();
	getchar();
	m.Stop();

	Socket::Term();
	return 0;
}


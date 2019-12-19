#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#else
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
typedef SimpleEventServiceT<DelayEventServiceT<Event,ThreadService>> ClientService;

#ifndef USE_UDP
#ifdef USE_EPOLL
typedef EPollSocketSetT<ClientService,client,DEFAULT_FD_SETSIZE> ClientSocketSet;
#elif defined(USE_IOCP)
typedef CompletionPortSocketSetT<ClientService,client,DEFAULT_FD_SETSIZE> ClientSocketSet;
#else
typedef SelectSocketSetT<ClientService,client,DEFAULT_FD_SETSIZE> ClientSocketSet;
#endif//
#endif//USE_UDP

class client
#ifndef USE_UDP
#ifndef USE_MANAGER
	: public SocketExImpl<client,SelectClientT<ClientService,SimpleSocketT<ConnectSocketT<SocketEx>>>>
#else
#ifdef USE_EPOLL
	: public SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<EPollSocketT<ClientSocketSet,SocketEx>>>>>
#elif defined(USE_IOCP)
	: public SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<CompletionPortSocketT<ClientSocketSet,SocketEx>>>>>
#else
	: public SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<SelectSocketT<ClientSocketSet,SocketEx>>>>>
#endif
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
#ifdef USE_EPOLL
	typedef SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<EPollSocketT<ClientSocketSet,SocketEx>>>>> Base;
#elif defined(USE_IOCP)
	typedef SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<CompletionPortSocketT<ClientSocketSet,SocketEx>>>>> Base;
#else
	typedef SocketExImpl<client,SimpleEvtSocketT<SimpleSocketT<ConnectSocketT<SelectSocketT<ClientSocketSet,SocketEx>>>>> Base;
#endif
#endif//USE_MANAGER
#else
#ifndef USE_MANAGER
	typedef SocketExImpl<client,SelectUdpClientT<ClientService,SimpleUdpSocketT<ConnectSocketT<SocketEx>>>> Base;
#else
	typedef SocketExT<client,SimpleSocketArchitectureT<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > Base;
#endif//USE_MANAGER
#endif//USE_UDP
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

protected:
	//
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

class manager 
#ifdef USE_MANAGER
: public SocketManagerT<ClientSocketSet>
#else
: public ThreadService
#endif//
{
#ifdef USE_MANAGER
	typedef SocketManagerT<ClientSocketSet> Base;
#else
	typedef ThreadService Base;
#endif//
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

	bool Start()
	{
		bool ret = Base::Start();
	#ifdef USE_MANAGER
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			std::shared_ptr<client> sp_client = std::make_shared<client>();
	#ifndef USE_UDP
			sp_client->Open();
	#else
			sp_client->Open(AF_INET,SOCK_DGRAM);
	#endif//
			AddSocket(sp_client);
			sp_client->Connect(DEFAULT_IP,DEFAULT_PORT);
		}
	#else
		c = new client[DEFAULT_CLIENT_COUNT];
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Start(DEFAULT_IP,DEFAULT_PORT);
		}
	#endif//
		return ret;
	}

	void Stop()
	{
		Base::Stop();
	#ifdef USE_MANAGER
	#else
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Stop();
		}
		delete []c;
	#endif//
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


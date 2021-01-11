#include "../samples.h"
#include "../../XSocket/XSocketImpl.h"
#if USE_EPOLL
#include "../../XSocket/XEPoll.h"
#elif USE_IOCP
#include "../../XSocket/XCompletionPort.h"
#else
#endif//
#if USE_OPENSSL
#include "../../XSocket/XSSLImpl.h"
#endif
#include "../../XSocket/XDNSImpl.h"
#include "../../XSocket/XSimpleImpl.h"
using namespace XSocket;

class client;

class Event : public DealyEventBase
{
public:
	client* dst = nullptr;
	int id;
	std::string buf;
#if USE_UDP
	SockAddrType addr;
#endif
	int flags;

	Event() {}
#if USE_UDP
	Event(client* d, int id, const char* buf, int len, const SockAddrType& addr, int flag):dst(d),id(id),buf(buf,len),addr(addr),flags(flag){}
#else
	Event(client* d, int id, const char* buf, int len, int flag):dst(d),id(id),buf(buf,len),flags(flag){}
#endif

	// inline int get_id() { return evt; }
	// inline const char* get_data() { return data.c_str(); }
	// inline int get_datalen() { return data.size(); }
	// inline int get_flags() { return flags; }
};
class EventService : public
#if USE_EPOLL
EventServiceT<Event,EPollService>
#elif USE_IOCP
EventServiceT<Event,CompletionPortService>
#else
EventServiceT<Event,SelectService>
#endif//
{
public:

	inline client* IsSocketEvent(const Event& evt)
	{
		return evt.dst;
	}
	inline bool IsActive(Event& evt) { return evt.IsActive(); }
};
typedef SimpleSocketEvtServiceT<EventService> ClientService;

#if  USE_UDP
typedef DNSClientSocketT<DNSUdpSocketT<SimpleUdpSocketT<ConnectSocketExT<SelectSocketT<ClientService,SocketEx>>,SockAddrType>>> ClientSocket;
#else
#if USE_EPOLL
typedef EPollSocketSetT<ClientService,client> ClientSocketSet;
#elif USE_IOCP
typedef CompletionPortSocketSetT<ClientService,client> ClientSocketSet;
#else
typedef SelectSocketSetT<ClientService,client> ClientSocketSet;
#endif//

#if USE_MANAGER
#if USE_EPOLL
typedef ConnectSocketExT<EPollSocketT<ClientSocketSet,SocketEx>> ClientSocketBase;
#elif USE_IOCP
typedef ConnectSocketExT<CompletionPortSocketT<ClientSocketSet,SocketEx>> ClientSocketBase;
#else
typedef ConnectSocketExT<SelectSocketT<ClientSocketSet,SocketEx>> ClientSocketBase;
#endif
#if USE_OPENSSL
typedef SSLConnectSocketT<DNSClientSocketT<DNSSocketT<SimpleSocketT<SSLSocketT<ClientSocketBase>>>>> ClientSocket;
#else 
typedef DNSClientSocketT<DNSSocketT<SimpleSocketT<ClientSocketBase>>> ClientSocket;
#endif
#else
typedef ConnectSocketExT<SocketEx> ClientSocket;
#endif//USE_MANAGER
#endif//USE_UDP

class client
#if USE_UDP
	: public SocketExImpl<client,SelectUdpClientT<ClientService,ClientSocket>>
#else
#if USE_MANAGER
	: public SocketExImpl<client,SimpleEvtSocketT<ClientSocket>>
#else
	: public SocketExImpl<client,SelectClientT<ClientService,ClientSocket>>
#endif//USE_MANAGER
#endif//USE_UDP
{
#if USE_UDP
	typedef SocketExImpl<client,SelectUdpClientT<ClientService,ClientSocket>> Base;
#else
#if USE_MANAGER
	typedef SocketExImpl<client,SimpleEvtSocketT<ClientSocket>> Base;
#else
	typedef SocketExImpl<client,SelectClientT<ClientService,ClientSocket>> Base;
#endif//USE_MANAGER
#endif//USE_UDP
protected:
	//std::once_flag start_flag_;
	std::string addr_;
	u_short port_;
public:
	client()
	{
		
	}

#if USE_MANAGER
#else
	bool Start(const std::string& addr, u_short port)
	{
		addr_ = addr;
		port_ = port;
		Base::Start();
		return true;
	}
protected:
	//
	bool OnStart()
	{
		if(!Base::OnStart()) {
			return false;
		}
	#if USE_UDP
		Open(addr_.c_str(),AF_INETType,SOCK_DGRAM);
		Select(FD_READ);
		SetNonBlock();//设为非阻塞模式
		SockAddrType stAddr = {0};
	#if USE_IPV6
		stAddr.sin6_family = AF_INET6;
		IpStr2IpAddr(addr_.c_str(),AF_INET6,&stAddr.sin6_addr);
		stAddr.sin6_port = htons((u_short)port_);
	#else
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = Ip2N(Url2Ip(addr_.c_str()));
		stAddr.sin_port = htons((u_short)port_);
	#endif//
		struct addrinfo ai = {0};
		ai.ai_family = AF_INETType;
		ai.ai_socktype = SOCK_DGRAM;
		ai.ai_flags = AI_PASSIVE;
		auto result = AsyncGetAddrInfo("www.baidu.com", "", &ai);
		std::future_status status;
		do {
			status = result.wait_for(std::chrono::milliseconds(10));
			switch (status)
			{
			case std::future_status::ready:
				LOG4D("AsyncGetAddrInfo Ready...");
				break;
			case std::future_status::timeout:
				LOG4D("AsyncGetAddrInfo Wait...");
				break;
			case std::future_status::deferred:
				LOG4D("AsyncGetAddrInfo Deferred...");
				break;
			default:
				break;
			}
	
		} while (status != std::future_status::ready);
		struct addrinfo* ai_result = result.get();
		DNS::Message msg;
		msg.Head().id = 1024;
		msg.Head().QR = DNS::QR_QUERY;
		msg.Head().opcode = DNS::OPCODE_QUERY;
		msg.Head().AA = 0;
		msg.Head().RD = 1;
		msg.Head().RA = 0;
		msg.Head().rcode = 0;
		msg.Head().Questions = 1;
		DNS::qrinfo_t qr;
		qr.name_ = "www.baidu.com";
		qr.type_ = DNS::TYPE_A;
		qr.class_ = DNS::CLASS_IN;
		msg.QRs().push_back(qr);
        XBuffer buff(DNS::DNS_DEF_DATA_SIZE,true);
		msg.Encode(buff);
		PostBuf(buff.data(),buff.size(),stAddr,SOCKET_PACKET_FLAG_TEMPBUF);
	#else
		Base::Connect(addr_.c_str(), port_);
	#endif//
		return true;
	}

	void OnStop()
	{
		if (IsSocket()) {
			ShutDown();
			Close();
		}
		Base::OnStop();
	}
#endif//USE_MANAGER

public:
#if USE_UDP
	inline void PostBuf(const char* lpBuf, int nBufLen, const SockAddrType& addr, int nFlags = 0)
	{
		LOG4D("PostBuf:%.*s", nBufLen, lpBuf);
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,addr,nFlags));
	}
#else
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		LOG4D("PostBuf:%.*s", nBufLen, lpBuf);
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}
#endif

	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
			if(!IsSocket()) {
				return;
			}
			LOG4D("SendBuf:%.*s", evt.buf.size(), evt.buf.c_str());
#if USE_UDP
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.addr);
#else
			SendBuf(evt.buf.c_str(),evt.buf.size());
#endif
		}
	}

protected:
	//
#if USE_UDP
#else
	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);
		if(!IsConnected()) {
			return;
		}
	}
#endif//
};

class manager 
#if USE_MANAGER
: public SocketManagerT<ClientSocketSet>
#else
: public ThreadService
#endif//
{
#if USE_MANAGER
	typedef SocketManagerT<ClientSocketSet> Base;
#else
	typedef ThreadService Base;
#endif//
protected:
	client *c;
public:

#if USE_MANAGER
	manager(int nMaxSocketCount):Base(nMaxSocketCount,DEFAULT_MAX_SOCKSET_COUNT)
#else
	manager(int nMaxSocketCount)
#endif
	{	
#if USE_MANAGER
		SetWaitTimeOut(DEFAULT_WAIT_TIMEOUT);
#endif//
	}
	~manager()
	{
		
	}

	bool Start()
	{
		bool ret = Base::Start();
	#if USE_MANAGER
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			std::shared_ptr<client> sp_client = std::make_shared<client>();
	#if USE_UDP
			sp_client->Open(AF_INET,SOCK_DGRAM);
			AddSocket(sp_client);
	#else
			sp_client->Open(DEFAULT_IP);
			AddConnect(sp_client,DEFAULT_PORT);
	#endif//
		}
	#else
		c = new client[DEFAULT_CLIENT_COUNT];
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Start(ChinaDNS1,DNSPort);
		}
	#endif//
		return ret;
	}

	void Stop()
	{
		Base::Stop();
	#if USE_MANAGER
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
int main(int argc, char* argv[])
#endif//
{
	client::Init();
#if USE_UDP
#else
#if USE_OPENSSL
	client::Configure();
#endif
#endif
	int client_count = DEFAULT_CLIENT_COUNT;
	if(argc > 1) {
		client_count = atoi(argv[1]);
	}
	manager m(client_count);
	m.Start();
	getchar();
	m.Stop();

	client::Term();
	return 0;
}


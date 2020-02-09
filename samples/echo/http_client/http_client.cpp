#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttpImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#endif//
#ifdef USE_OPENSSL
#include "../../../XSocket/XSSLImpl.h"
#endif
using namespace XSocket;
#include <random>

/* 测试的HTTP报文 */
const std::string http_get_raw = "GET /favicon.ico HTTP/1.1\r\n"
         "Host: 0.0.0.0=5000\r\n"
         "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\n"
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
         "Accept-Language: en-us,en;q=0.5\r\n"
         "Accept-Encoding: gzip,deflate\r\n"
         "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
         "Keep-Alive: 300\r\n"
         "Connection: keep-alive\r\n"
         "\r\n";
const std::string http_post_raw =  "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\n"
         "Accept: */*\r\n"
         "Transfer-Encoding: identity\r\n"
         "Content-Length: 5\r\n"
         "\r\n"
         "World";
// trunk编码的报文后，含有托挂的字段
// 详细请参考《HTTP权威指南》编码的部分
const std::string http_trunk_head =  "POST /chunked_w_trailing_headers HTTP/1.1\r\n"
         "Transfer-Encoding: chunked\r\n"
         "\r\n"
         "5\r\nhello\r\n"
         "6\r\n world\r\n"
         "0\r\n"
         "Vary: *\r\n"
         "Content-Type: text/plain\r\n"
         "\r\n";
const std::string http_trunk_head1 = "POST /two_chunks_mult_zero_end HTTP/1.1\r\n"
         "Transfer-Encoding: chunked\r\n"
         "\r\n"
         "5\r\nhello\r\n"
         "6\r\n world\r\n"
         "000\r\n"
         "\r\n";
const std::string http_trunk_part_1 =  "POST /chunked_w_trailing_headers HTTP/1.1\r\n"
         "Transfer-Encoding: chunked\r\n"
         "\r\n"
         "5\r\nhello\r\n";
const std::string http_trunk_part_2 = "6\r\n world\r\n"
         "0\r\n"
         "Vary: *\r\n"
         "Content-Type: text/plain\r\n"
         "\r\n";

class client;

class Event : public DealyEventBase
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
class ClientEventService : public
EventServiceT<Event,SelectService>
{
public:

	inline client* IsSocketEvent(const Event& evt)
	{
		return evt.dst;
	}
	inline bool IsActive(Event& evt) { return evt.IsActive(); }
	inline bool IsRepeat(Event& evt) { return evt.IsRepeat(); }
	inline void UpdateRepeat(Event& evt) { evt.Update(); }
};
typedef SimpleSocketEvtServiceT<ClientEventService> ClientService;

#ifdef USE_OPENSSL
typedef SSLConnectSocketT<SimpleSocketT<SSLSocketT<ConnectSocketT<SelectSocketT<ClientService,SocketEx>>>>> ClientSocket;
#else 
typedef SimpleSocketT<ConnectSocketT<SelectSocketT<ClientService,SocketEx>>> ClientSocket;
#endif
class client: public SocketExImpl<client,SelectClientT<ClientService,HttpReqSocketT<ClientSocket>>>
{
	typedef SocketExImpl<client,SelectClientT<ClientService,HttpReqSocketT<ClientSocket>>> Base;
protected:
	//std::once_flag start_flag_;
	std::string addr_;
	u_short port_;
public:
	client()
	{
#ifdef USE_WEBSOCKET
		EnableWSCache(true);
#endif
	}

	bool Start(const std::string& addr, u_short port)
	{
		addr_ = addr;
		port_ = port;
		return Base::Start();
	}
protected:
	//
	bool OnInit()
	{
		if(!Base::OnInit()) {
			return false;
		}
		Open();
		SOCKADDR_IN stAddr = {0};
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = Ip2N(Url2Ip(addr_.c_str()));
		stAddr.sin_port = htons((u_short)port_);
		Connect((SOCKADDR*)&stAddr, sizeof(stAddr));

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
	virtual void OnMessage(const HttpBufferMessage& msg)
	{
		if(msg.size())
			PRINTF("%.19s", msg.data());
		Base::OnMessage(msg);
	}

	virtual void OnUpgrade(const HttpBufferMessage& msg)
	{
		static std::default_random_engine random;
#ifdef USE_WEBSOCKET
		SendWSBuf("hello.", 6, SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL, random());
#endif
	}
#ifdef USE_WEBSOCKET
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{
		PRINTF("%d %.19s", nBufLen, lpBuf);
		SendWSBuf("hello.", 6, SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL);
	}
#endif
#ifdef USE_OPENSSL
	virtual void OnSSLConnect()
	{
#ifdef USE_WEBSOCKET
		SendWSUpgrade("localhost");
#else
		PRINTF("%s",http_get_raw.c_str());
		SendBuf(http_get_raw.c_str(),http_get_raw.size(),0);
#endif
	}
#endif
	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);
		if(!IsConnected()) {
			return;
		}
#ifndef USE_OPENSSL
#ifdef USE_WEBSOCKET
		SendWSUpgrade("localhost");
#else
		PRINTF("%s",http_get_raw.c_str());
		HttpParser parser;
		int nParseLen = http_get_raw.size();
		parser.ParseBuf(http_get_raw.c_str(),nParseLen);
		const auto& msgs = parser.messages();
		if(msgs.size()) {
			std::shared_ptr<HttpRequest> req = std::make_shared<HttpRequest>();
			msgs.back().to_request(*req);
			std::promise<std::shared_ptr<HttpResponse>> rsp;
			std::future<std::shared_ptr<HttpResponse>> ret = rsp.get_future();
			SendHttpRequest(req,std::move(rsp));
		}
		//SendBuf(http_get_raw.c_str(),http_get_raw.size(),0);
#endif
#endif
	}
};

class manager : public ThreadService
{
protected:
	client *c;
public:
	manager(int nMaxSocketCount)
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
			c[i].Start("www.baidu.com",
#ifdef USE_OPENSSL
			443);
#else
			80);
#endif
			//c[i].Start(DEFAULT_IP,DEFAULT_PORT);
		}
		return true;
	}

	virtual void OnTerm()
	{
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Stop();
		}
		delete []c;
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	client::Init();
#ifdef USE_OPENSSL
	client::Configure();
#endif
	
	manager m(DEFAULT_CLIENT_COUNT);
	m.Start();
	getchar();
	m.Stop();

	client::Term();
	return 0;
}


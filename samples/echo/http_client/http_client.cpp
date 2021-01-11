#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttpImpl.h"
#if USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#endif//
#if USE_OPENSSL
#include "../../../XSocket/XSSLImpl.h"
#endif
#include "../../../XSocket/XSimpleImpl.h"
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
         "Connection: close\r\n"
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

typedef TaskServiceExT<SelectService> ClientService;

#if USE_OPENSSL
typedef BasicSocketT<GracefulSocketT<SSLConnectSocketT<SimpleSocketT<SSLSocketT<ConnectSocketExT<SelectSocketT<ClientService,SocketEx>>>>>>> ClientSocket;
#else 
typedef BasicSocketT<GracefulSocketT<SimpleSocketT<ConnectSocketExT<SelectSocketT<ClientService,SocketEx>>>>> ClientSocket;
#endif
class client
#if USE_OPENSSL
: public HttpsReqSocketImpl<client,SelectClientT<ClientService,HttpSocketT<ClientSocket>>>
#else
: public HttpReqSocketImpl<client,SelectClientT<ClientService,HttpSocketT<ClientSocket>>>
#endif//
{
#if USE_OPENSSL
	typedef HttpsReqSocketImpl<client,SelectClientT<ClientService,HttpSocketT<ClientSocket>>> Base;
#else
	typedef HttpReqSocketImpl<client,SelectClientT<ClientService,HttpSocketT<ClientSocket>>> Base;
#endif
protected:
	//std::once_flag start_flag_;
	std::string addr_;
	u_short port_;
public:
	client()
	{
#if USE_UDP
#else
		ReserveRecvBufSize(DEFAULT_BUFSIZE);
		ReserveSendBufSize(DEFAULT_BUFSIZE);
#if USE_WEBSOCKET
		EnableWSCache(true);
#endif
#endif//USE_UDP
	}

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
		struct addrinfo hints = {0};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;
		PostGetAddrInfo(addr_,"",hints,std::bind(&client::OnResolve,shared_from_this(),std::placeholders::_1));
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

	void OnResolve(struct addrinfo* result)
	{
		if(IsStopFlag()) {
			return;
		}
		if(INVALID_SOCKET == Open(result)) {
			return;
		}
		Connect(port_);
	}

protected:
	//
	virtual void OnMessage(const std::shared_ptr<Message>& msg)
	{
		// if(msg->size())
		// 	LOG4D("%.19s", msg->data());
		Base::OnMessage(msg);
	}

	virtual void OnUpgrade(const std::shared_ptr<Message>& msg)
	{
		static std::default_random_engine random;
#if USE_WEBSOCKET
		SendWSBuf("hello.", 6, SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL, random());
#endif
	}
#if USE_WEBSOCKET
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{
		LOG4D("%d %.19s", nBufLen, lpBuf);
		SendWSBuf("hello.", 6, SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL);
	}
#endif
#if USE_OPENSSL
	virtual void OnSSLConnect()
	{
		Base::OnSSLConnect();
#if USE_WEBSOCKET
		SendWSUpgrade("localhost");
#else
		//LOG4D("%s",http_get_raw.c_str());
		//SendBuf(http_get_raw.c_str(),http_get_raw.size(),0);
#endif
	}
#endif
	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);
		if(!IsConnected()) {
			return;
		}
#if USE_OPENSSL
#else
#if USE_WEBSOCKET
		SendWSUpgrade("localhost");
#else
		/*LOG4D("%s",http_get_raw.c_str());
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
		}*/
		//SendBuf(http_get_raw.c_str(),http_get_raw.size(),0);
#endif
#endif
	}
};

class manager : public ThreadService
{
protected:
	std::vector<std::shared_ptr<client>> c;
public:
	manager(int nMaxSocketCount)
	{
		
	}
	~manager()
	{
		
	}

	virtual bool OnStart()
	{
		std::time_t tt = std::time(nullptr);
		tt = std::mktime(std::localtime(&tt));
		tt = HttpMessage::gm2localtime(HttpMessage::local2gmtime(tt));
		auto strgmt = HttpMessage::gmtime2str(tt, "%a, %d %b %Y %H:%M:%S GMT"); //0时区
		LOG4D("%s",strgmt.c_str());
		LOG4D("%s",HttpMessage::localtime2str(tt, "%a, %d %b %Y %H:%M:%S GMT").c_str()); //8时区
		LOG4D("%s",HttpMessage::httptime2str(HttpMessage::str2httptime(strgmt.c_str())).c_str());
		c.resize(DEFAULT_CLIENT_COUNT);
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i] = std::make_shared<client>();
// 			c[i].Start("www.baidu.com",
// #if USE_OPENSSL
// 			443);
// #else
// 			80);
// #endif
			c[i]->Start(DEFAULT_IP,DEFAULT_PORT);
#if USE_WEBSOCKET
#else
			std::shared_ptr<client::RequestInfo> req_info = std::make_shared<client::RequestInfo>();
			req_info->req_.set_method(HTTP_GET);
			req_info->req_.set_url("/test/echo");
			req_info->req_.set_field("Accept-Encoding", "gzip");
			req_info->rsp_ = [] (std::shared_ptr<HttpResponse> rsp, bool last) {
				LOG4D("%s",rsp->to_string().c_str());
			};
			c[i]->PostHttpRequest(req_info);
#endif
		}
		return true;
	}

	virtual void OnStop()
	{
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i]->Stop();
		}
		c.clear();
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	client::Init();
#if USE_OPENSSL
	client::Configure();
#endif
	
	manager m(DEFAULT_CLIENT_COUNT);
	m.Start();

	getchar();

	ThreadPool::Inst().Stop();
	
	m.Stop();

	client::Term();
	return 0;
}


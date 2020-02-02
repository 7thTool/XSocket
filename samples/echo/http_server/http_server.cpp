// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttpImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//
#ifdef USE_OPENSSL
#include "../../../XSocket/XSSLImpl.h"
#endif
using namespace XSocket;

class worker;

class WorkService : public
#ifdef USE_EPOLL
SimpleTaskServiceT<EPollService>
#elif defined(USE_IOCP)
SimpleTaskServiceT<CompletionPortService>
#else
SimpleTaskServiceT<SelectService>
#endif//
{
public:
};

#ifdef USE_EPOLL
typedef EPollSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
typedef EPollSocketT<WorkSocketSet,SocketEx> WorkSocket;
#elif defined(USE_IOCP)
typedef CompletionPortSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
typedef CompletionPortSocketT<WorkSocketSet,SocketEx> WorkSocket;
#else
typedef SelectSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
typedef SelectSocketT<WorkSocketSet,SocketEx> WorkSocket;
#endif//

class worker
#ifdef USE_OPENSSL
	: public SocketExImpl<worker,SimpleSvrSocketT<HttpSocketT<SSLWorkSocketT<SimpleSocketT<WorkSocketT<SSLSocketT<WorkSocket>>>>>>>
#else
	: public SocketExImpl<worker,SimpleSvrSocketT<HttpSocketT<SimpleSocketT<WorkSocketT<WorkSocket>>>>>
#endif
{
#ifdef USE_OPENSSL
	typedef SocketExImpl<worker,SimpleSvrSocketT<HttpSocketT<SSLWorkSocketT<SimpleSocketT<WorkSocketT<SSLSocketT<WorkSocket>>>>>>> Base;
#else
	typedef SocketExImpl<worker,SimpleSvrSocketT<HttpSocketT<SimpleSocketT<WorkSocketT<WorkSocket>>>>> Base;
#endif
public:
	worker()
	{
		
	}

	~worker() 
	{
		
	}

public:
	//
	inline void PostBuf(const std::string& Buf, int nFlags = 0)
	{
		//this_service()->Post(std::function<void()>([this,Buf,nFlags](){ SendBuf(Buf, nFlags); }));
		this_service()->Post(std::bind((int (worker::*)(const std::string&, int ))&worker::SendBuf, this, Buf, nFlags), this, 3000, 10);
	}
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		auto buf = std::make_shared<std::string>(lpBuf,nBufLen);
		this_service()->Post(std::function<void()>([this,buf,nFlags](){ SendBuf(buf->c_str(), buf->size(), nFlags); }));
		/*以下是bind，package、future使用方法
		//auto task = std::bind((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen, nFlags);
		this_service()->Post(this_service()->Package((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen, nFlags));
		// auto task = std::make_shared< std::packaged_task<int()> >(
		// 		std::bind((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen, nFlags)
		// 	);
		std::future<int> fu;
		this_service()->Post(this_service()->Package(fu, (int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen, nFlags));
		*/
	}

protected:
	//
	virtual void OnMessage(const HttpRequest& req)
	{
		if(req.body_.first)
			PRINTF("%79s", req.body_.first);
		std::ostringstream ss;
		ss << "HTTP/1.1 200 OK\r\n"
		"Connection: close\r\n"
		"\r\n";
		ss.write(req.body_.first,req.body_.second);
		std::string buf = ss.str();
		PostBuf(buf);
	}

#ifdef USE_WEBSOCKET
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{
			auto body = request_.GetBody();
			SendWebSocketBuf(body.first, body.second, WS_OP_TEXT);
			SendWebSocketBuf(body.first, body.second, 0);
			SendWebSocketBuf(body.first, body.second, WS_FINAL_FRAME);
	}
#endif
};

class server 
	: public SelectServerT<SelectService,SocketExImpl<server,ListenSocketT<SelectSocketT<SelectService,SocketEx>>>,WorkSocketSet>
{
	typedef SelectServerT<SelectService,SocketExImpl<server,ListenSocketT<SelectSocketT<SelectService,SocketEx>>>,WorkSocketSet> Base;
public:
	server(int nMaxSocketCount = DEFAULT_MAX_FD_SETSIZE):Base(nMaxSocketCount)
	{

	}
	
	bool OnChar(char c)
	{
		switch(c)
		{
		case 'x':
		case 'X':
			printf("server worker count is [%d]", GetSocketCount());
			break;
		case 'q':
		case 'Q':
			return false;
			break;
		}
		return true;
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	worker::Init();
#ifdef USE_OPENSSL
	TLSContextConfig tls_ctx_config = {0};
	tls_ctx_config.cert_file = "./ssl/dev.crt";
    tls_ctx_config.key_file = "./ssl/dev_nopass.key";
    tls_ctx_config.dh_params_file;
    tls_ctx_config.ca_cert_file = "./ssl/dev.crt";
    tls_ctx_config.ca_cert_dir = "./ssl";
    tls_ctx_config.protocols = "TLSv1.1 TLSv1.2";
    tls_ctx_config.ciphers;
    tls_ctx_config.ciphersuites;
    tls_ctx_config.prefer_server_ciphers;
	worker::Configure(&tls_ctx_config);
#endif
	server *s = new server();
	s->Start(DEFAULT_IP, DEFAULT_PORT);
	getchar();
	s->Stop();
	delete s;

	worker::Term();

	return 0;
}


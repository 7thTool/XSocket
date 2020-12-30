// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttpImpl.h"
#if USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif USE_IOCP
#include "../../../XSocket/XCompletionPort.h"
#endif//
#if USE_OPENSSL
#include "../../../XSocket/XSSLImpl.h"
#endif
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>
#include <iostream>
#include <algorithm>
#include <fstream>


#ifdef _WIN32
#ifndef stat
#define stat _stat
#endif
#ifndef fstat
#define fstat _fstat
#endif
#ifndef open
#define open _open
#endif
#ifndef close
#define close _close
#endif
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif
#endif /* _WIN32 */

char uri_root[512];

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = {
	{ "txt", "text/plain" },
	{ "c", "text/plain" },
	{ "h", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/htm" },
	{ "css", "text/css" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ "pdf", "application/pdf" },
	{ "ps", "application/postscript" },
	{ NULL, NULL },
};

class worker;

class WorkService : public
#if USE_EPOLL
TaskServiceT<EPollService>
#elif USE_IOCP
TaskServiceT<CompletionPortService>
#else
TaskServiceT<SelectService>
#endif//
{
#if USE_EPOLL
typedef TaskServiceT<EPollService> Base;
#elif USE_IOCP
typedef TaskServiceT<CompletionPortService> Base;
#else
typedef TaskServiceT<SelectService> Base;
#endif// 
public:

protected:
	//
	bool OnStart() override
	{
		bool ret = Base::OnStart();
		if(!ret) {
			return false;
		}
		TaskID t = Post(3000, []{
			std::cout << "WorkService dealy test" << std::endl;
		});
		TaskID t2 = Post(5000, [this,t]{
			std::cout << "WorkService cancel test" << std::endl;
			Cancel(t);
		});
		TaskID t3 = Post(2000, [this,t2]{
			Cancel(t2);
			std::cout << "WorkServicecancel cancel test" << std::endl;
		});
		return ret;
	}

};

#if USE_EPOLL
typedef EPollSocketSetT<WorkService,worker> WorkSocketSet;
typedef EPollSocketT<WorkSocketSet,SocketEx> WorkSocket;
#elif USE_IOCP
typedef CompletionPortSocketSetT<WorkService,worker> WorkSocketSet;
typedef CompletionPortSocketT<WorkSocketSet,SocketEx> WorkSocket;
#else
typedef SelectSocketSetT<WorkService,worker> WorkSocketSet;
typedef SelectSocketT<WorkSocketSet,SocketEx> WorkSocket;
#endif//

class worker
#if USE_OPENSSL
	: public HttpRspSocketImpl<worker,TaskSocketT<HttpSocketT<SSLWorkSocketT<SimpleSocketT<WorkSocketT<SSLSocketT<WorkSocket>>>>>>>
#else
	: public HttpRspSocketImpl<worker,TaskSocketT<HttpSocketT<SimpleSocketT<WorkSocketT<WorkSocket>>>>>
#endif
{
#if USE_OPENSSL
	typedef HttpRspSocketImpl<worker,TaskSocketT<HttpSocketT<SSLWorkSocketT<SimpleSocketT<WorkSocketT<SSLSocketT<WorkSocket>>>>>>> Base;
#else
	typedef HttpRspSocketImpl<worker,TaskSocketT<HttpSocketT<SimpleSocketT<WorkSocketT<WorkSocket>>>>> Base;
#endif
public:
	worker()
	{
		ReserveRecvBufSize(DEFAULT_BUFSIZE);
		ReserveSendBufSize(DEFAULT_BUFSIZE);
	}

	~worker() 
	{
		
	}

public:
	//
	inline void PostBuf(const SendBuffer& Buf)
	{
		//this_service()->Post(std::function<void()>([spWorker = shared_from_this(),Buf](){ spWorker->SendBuf(Buf); }));
		//this_service()->Post(3000, std::bind((void (worker::*)(const SendBuffer&))&worker::SendBuf, this, Buf));
		//std::future<int> fu;
		//this_service()->Post(this_service()->Package(fu, (int (worker::*)(const std::string&, int ))&worker::SendBuf, this, Buf));
	}
	inline void PostBuf(const char* lpBuf, int nBufLen)
	{
		//auto buf = std::make_shared<std::string>(lpBuf,nBufLen);
		//this_service()->Post(std::function<void()>([this,buf](){ SendBuf(buf->c_str(), buf->size()); }));
		/*以下是bind，package、future使用方法
		//auto task = std::bind((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen);
		this_service()->Post(this_service()->Package((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen));
		// auto task = std::make_shared< std::packaged_task<int()> >(
		// 		std::bind((int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen)
		// 	);
		std::future<int> fu;
		this_service()->Post(this_service()->Package(fu, (int (worker::*)(const char*, int, int ))&worker::SendBuf, this, lpBuf, nBufLen));
		*/
	}

protected:
	//
	/*virtual void OnMessage(const HttpBufferMessage& msg)
	{
		if(msg.size())
			PRINTF("%.19s", msg.data());
		HttpResponse rsp;
		rsp.set_code(200);
		//msg.field("Content-type")
		rsp.set_field("Content-type", "text/html");
		rsp.set_field("Content-Length", tostr(msg.size()));
		rsp.set_data(std::string(msg.data(),msg.size()));
		this_service()->Post(std::bind((void (worker::*)(HttpBufferMessage& req, HttpResponse&))&worker::SendHttpResponse, this, msg, rsp), this);
	}*/

#if USE_WEBSOCKET
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{
		static std::default_random_engine random;
		std::string buf(lpBuf,nBufLen);
		for(size_t i = 0; i < 10; i++)
		{
			buf += buf;
		}
		SendWSBuf(buf.c_str(), buf.size(), SOCKET_PACKET_OP_TEXT
		//, random()
		);
		SendWSBuf(buf.c_str(), buf.size(), 0
		//, random()
		);
		SendWSBuf(buf.c_str(), buf.size(), SOCKET_PACKET_FLAG_FINAL);
	}
#endif
};
// Return a reasonable mime type based on the extension of a file.
    const char* mime_type(const char* str, int len)
    {
        if(str && len) {
            const char* ext = nullptr;
            const char* p = str + len - 1;
            while(p != str) { 
                if(*p == '.') {
                    ext = p;
                    break;
                }
                --p;
            }
            if(ext) {
                if(strcmp(ext, ".htm") == 0)  return "text/html";
                if(strcmp(ext, ".html") == 0) return "text/html";
                if(strcmp(ext, ".php") == 0)  return "text/html";
                if(strcmp(ext, ".css") == 0)  return "text/css";
                if(strcmp(ext, ".txt") == 0)  return "text/plain";
                if(strcmp(ext, ".js") == 0)   return "application/javascript";
                if(strcmp(ext, ".json") == 0) return "application/json";
                if(strcmp(ext, ".xml") == 0)  return "application/xml";
                if(strcmp(ext, ".swf") == 0)  return "application/x-shockwave-flash";
                if(strcmp(ext, ".flv") == 0)  return "video/x-flv";
                if(strcmp(ext, ".png") == 0)  return "image/png";
                if(strcmp(ext, ".jpe") == 0)  return "image/jpeg";
                if(strcmp(ext, ".jpeg") == 0) return "image/jpeg";
                if(strcmp(ext, ".jpg") == 0)  return "image/jpeg";
                if(strcmp(ext, ".gif") == 0)  return "image/gif";
                if(strcmp(ext, ".bmp") == 0)  return "image/bmp";
                if(strcmp(ext, ".ico") == 0)  return "image/vnd.microsoft.icon";
                if(strcmp(ext, ".tiff") == 0) return "image/tiff";
                if(strcmp(ext, ".tif") == 0)  return "image/tiff";
                if(strcmp(ext, ".svg") == 0)  return "image/svg+xml";
                if(strcmp(ext, ".svgz") == 0) return "image/svg+xml";
                return "application/octet-stream";
            }
        }
        return "application/text";
    }

class HttpHandler : public TaskServiceT<ThreadCVService>
{
	typedef TaskServiceT<ThreadCVService> Base;
public:
	HttpHandler():Base()
	{
		worker::Router().ANY("/",std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		worker::Router().GET("/test/echo",std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		worker::Router().GET("test/echo",std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		worker::Router().GET("test/multicast/hello",std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		worker::Router().GET("test/echo/hello",std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		worker::Router().ROOT(HTTP_POST).Path("test").Path("echo").Path("hello").Set(std::bind(&HttpHandler::OnMessage,this,std::placeholders::_1, std::placeholders::_2));
		
		worker::Router().GET("/rdi",std::bind(&HttpHandler::OnChunkTest,this,std::placeholders::_1, std::placeholders::_2));
	}

protected:
	//
	bool OnStart() override
	{
		bool ret = Base::OnStart();
		if(!ret) {
			return false;
		}
		TaskID t = Post(3000, []{
			std::cout << "HttpHandler dealy test" << std::endl;
		});
		TaskID t2 = Post(5000, [this,t]{
			std::cout << "HttpHandler cancel test" << std::endl;
			Cancel(t);
		});
		TaskID t3 = Post(2000, [this,t2]{
			Cancel(t2);
			std::cout << "HttpHandlercancel cancel test" << std::endl;
		});
		return ret;
	}

	void OnMessage(std::shared_ptr<worker> http, std::shared_ptr<HttpRequest> req)
	{
		//std::async(//std::launch::async|std::launch::deferred,
		ThreadPool::Inst().Post(
			[http,req] {
			if(req->size())
				PRINTF("%.19s", req->data());
			auto data = req->to_string();
			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
			rsp->set_code(200);
			//msg.field("Content-type")
			rsp->set_field("Content-type", "text/html");
			rsp->set_field("Connection", "close");
#if 1
			rsp->set_chunked();
			rsp->set_data(data);
			http->PostHttpResponse(rsp);
			http->PostHttpChunk(ObjectPool::make_shared<String>(std::move(data)), true);
			//http->PostHttpChunk(nullptr);
#else
			rsp->set_field("Content-Length", tostr(data.size()));
			rsp->set_data(std::move(data));
			http->PostHttpResponse(rsp);
#endif
		});
	}

	void OnChunkTest(std::shared_ptr<worker> ep, std::shared_ptr<HttpRequest> req)
    {
        //ThreadPool::Inst().Post([this,ep,req](){

        // Returns a Not Modified response
        auto const not_modified =
        [&ep, &req](const String& target)
        {
			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
            rsp->set_code(304);
			//rsp->set_field("Content-type", "text/html");
			rsp->set_field("Connection", req->field("Connection", "close"));
			rsp->set_field("Server", "http_server");
            //rsp->set_data("The resource '" + target + "' was not modified.");
			ep->PostHttpResponse(rsp);
        };

        // Returns a bad request response
        auto const bad_request =
        [&ep, &req](const String& why)
        {
			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
            rsp->set_code(400);
			rsp->set_field("Content-type", "text/html");
			rsp->set_field("Connection", req->field("Connection", "close"));
			rsp->set_field("Server", "http_server");
            rsp->set_data(why);
			ep->PostHttpResponse(rsp);
        };

        // Returns a not found response
        auto const not_found =
        [&ep, &req](const String& target)
        {
			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
            rsp->set_code(404);
			rsp->set_field("Content-type", "text/html");
			rsp->set_field("Connection", req->field("Connection", "close"));
			rsp->set_field("Server", "http_server");
            rsp->set_data("The resource '" + target + "' was not found.");
			ep->PostHttpResponse(rsp);
        };

        // Returns a server error response
        auto const server_error =
        [&ep, &req](const String& what)
        {
			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
            rsp->set_code(500);
			rsp->set_field("Content-type", "text/html");
			rsp->set_field("Connection", req->field("Connection", "close"));
			rsp->set_field("Server", "http_server");
            rsp->set_data("An error occurred: '" + what + "'");
			ep->PostHttpResponse(rsp);
        };

        printf("%s\n", req->to_string().c_str());

        // Make sure we can handle the method
        if( req->method() != HTTP_GET &&
            req->method() != HTTP_HEAD) {
            bad_request("Unknown HTTP-method");
            return;
        }

        // Request path must be absolute and not contain "..".
        size_t urllen = 0;
        auto url = req->url(&urllen);
        if( !urllen || url[0] != '/' || strnstr(url, urllen, "..")) {
            bad_request("Illegal request-target");
            return;
        }

        //try  {
            std::ifstream file(std::string(".")+url, ios::in | ios::binary);
            file.seekg(0, file.end);
            size_t total_size = file.tellg();
            file.seekg(0, file.beg);

			std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
            rsp->set_code(200);
            rsp->set_field("Date", HttpMessage::httptime2str());
            //rsp->set_field("Last-Modified", last_modified);
            //rsp->set_field("Etag", rdi_etag_);
            //rsp->set_field("Accept-Ranges", "bytes");
            //rsp->set_field("Content-Range", "bytes 0-2000/4932");
            //rsp->set_field("Content-Encoding", "");
			rsp->set_field("Content-type", mime_type(url, urllen));
			rsp->set_field("Connection", req->field("Connection", "close"));
			rsp->set_field("Server", "http_server");
            if(req->method() == HTTP_GET)  {
                String body;
                auto not_send_size = total_size;
                body.resize(std::min<>(not_send_size, (size_t)4096));
                if(body.size() == file.read((char*)body.data(), body.size()).gcount()) {
                    rsp->set_data(body);
                    if(body.size() < not_send_size) {
                        not_send_size -= body.size();
                        rsp->set_chunked();
                        ep->PostHttpResponse(rsp);
                        do {
                            auto chunk = ObjectPool::make_shared<String>();
                            chunk->resize(std::min<>(not_send_size, (size_t)4096));
                            if(chunk->size() == file.read((char*)chunk->data(), chunk->size()).gcount()) {
                                bool last = chunk->size() >= not_send_size;
                                ep->PostHttpChunk(chunk, last);
                                if(!last) {
                                    not_send_size -= chunk->size();
                                } else {
                                    break;
                                }
                            } else {
                                ep->Post([ep](){ 
                                    ep->Close(); 
                                });
                                break;
                            }
                        } while(true);
                    } else {
                        ep->PostHttpResponse(rsp);
                    }
                } else {
                    ep->Post([ep](){ 
                        ep->Close(); 
                    });
                }
            } else {
			    ep->PostHttpResponse(rsp);
            }
        //} catch (const std::exception &e) {
        //    server_error(e.what());
        //}

        //});
    }
};

class server 
	: public SelectServerT<SelectService,SocketExImpl<server,ListenSocketT<SelectSocketT<SelectService,SocketEx>>>,WorkSocketSet>
{
	typedef SelectServerT<SelectService,SocketExImpl<server,ListenSocketT<SelectSocketT<SelectService,SocketEx>>>,WorkSocketSet> Base;
public:
	server(int nMaxSocketCount = DEFAULT_MAX_SOCKSET_COUNT):Base(nMaxSocketCount,DEFAULT_MAX_SOCKSET_COUNT)
	{
		SetWaitTimeOut(DEFAULT_WAIT_TIMEOUT);
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

void test(int & i)
{
	PRINTF("test(int & i)");
}

void test(int && i)
{
	PRINTF("test(int && i)");
}

void test_right(int&& i)
{
	test(i); //left
	test(std::move(i)); //right
	test(std::forward<int>(i)); //right
	//File: ..\samples\echo\http_server\http_server.cpp, Line: 184: test(int & i)
	//File: ..\samples\echo\http_server\http_server.cpp, Line: 189: test(int && i)
	//File: ..\samples\echo\http_server\http_server.cpp, Line: 189: test(int && i)
}

void test_rbtree()
{
	std::set<int> intset = { 1,2,3,4,5,6,7,8,9};
	auto it = intset.find(3);
	//intset.erase(it);//删除后it无效，会抛出异常
	it = intset.erase(it); //指向下一个有效it
	if(it != intset.end()) {
		PRINTF("test_rbtree %d", *it);
	} else {
		PRINTF("test_rbtree end");
	}
}

void test()
{
	std::string str("abc");
	std::ostringstream oss(str, std::ios_base::app);
	oss << "123";
	PRINTF("oss=%s str=%s", oss.str().c_str(), str.c_str());
	int i = 10000;
	test_right(std::move(i));
	test(-i);
	test_rbtree();
	ThreadPool::Inst().Post([]{
		PRINTF("ThreadPool test");
	});
}

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	test();

	worker::Init();
#if USE_OPENSSL
	TLSContextConfig tls_ctx_config = {0};
	tls_ctx_config.cert_file = "./ssl/dev.crt";
    tls_ctx_config.key_file = "./ssl/dev_nopass.key";
    tls_ctx_config.dh_params_file;
    tls_ctx_config.ca_cert_file = "./ssl/dev.crt";
    tls_ctx_config.ca_cert_dir = "./ssl";
    tls_ctx_config.protocols = "TLSv1 TLSv1.1 TLSv1.2";
    tls_ctx_config.ciphers = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;";
    tls_ctx_config.ciphersuites;
    tls_ctx_config.prefer_server_ciphers = 1;
	worker::Configure(&tls_ctx_config);
#endif

	HttpHandler h;
	h.Start();

	server *s = new server();
	s->Start("0.0.0.0", DEFAULT_PORT);
	getchar();
	s->Stop();
	delete s;

	h.Stop();

	worker::Term();

	return 0;
}


// client.cpp : 定义控制台应用程序的入口点。
//
#define USE_ZLIB 0
#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XMSQuicImpl.h"
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class client;
class handler;

class request : public msquic::Stream<request,handler>
{
	typedef msquic::Stream<request,handler> Base;
public:
	std::function<void()> cb;
protected:
	//
	QUIC_STATUS OnEvent(const QUIC_STREAM_EVENT& evt)
	{
		switch (evt.Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			cb();
            break;
        default:
            break;
        }
		return Base::OnEvent(evt);
	}
};

typedef TaskServiceT<ThreadCVService> handler_service;
class handler : public msquic::Connection<handler,client,CVSocketT<handler_service,SocketEx>>
{
	typedef msquic::Connection<handler,client,CVSocketT<handler_service,SocketEx>> Base;
public:
};
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{
	typedef SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE> Base;
};
class client : public msquic::Client<client,handler_set>
{
	typedef msquic::Client<client,handler_set> Base;
public:
	client(int max_handler_count):Base((max_handler_count+handler_set::GetMaxSocketCount()-1)/handler_set::GetMaxSocketCount())
	{
		
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
	TLSContextConfig tls_ctx_config = {0};
	tls_ctx_config.cert_file = "./ssl/dev.crt";
    tls_ctx_config.key_file = "./ssl/dev_nopass.key";
    tls_ctx_config.dh_params_file;
    tls_ctx_config.ca_cert_file = "./ssl/dev.crt";
    tls_ctx_config.ca_cert_dir = "./ssl";
    tls_ctx_config.protocols = "TLSv1.1 TLSv1.2";
    tls_ctx_config.ciphers;
    tls_ctx_config.ciphersuites;
    tls_ctx_config.prefer_client_ciphers;
	//worker::Configure(&tls_ctx_config);
#endif

	auto c = std::make_shared<client>(DEFAULT_MAX_FD_SETSIZE);
	c->Start();

	auto h = std:make_shared<handler>();
	c->AddSocket(h);
	h->Post([h](){
		h->Open(DEFAULT_IP,DEFAULT_PORT);
		auto req = std::make_shared<request>(h);
		req->cb = [h,req](){
			;
		};
	});

	getchar();

	c->Stop();
	c.reset();

	client::Term();

	return 0;
}


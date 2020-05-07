// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XMSQuicImpl.h"
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class server;

typedef TaskServiceT<ThreadCVService> handler_service;
class handler : public msquic::Connection<handler,server,CVSocketT<handler_service,SocketEx>>
{
	typedef msquic::Connection<handler,server,CVSocketT<handler_service,SocketEx>> Base;
public:
};
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{
	typedef SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE> Base;
};
class server : public msquic::Server<server,handler_set>
{
	typedef msquic::Server<server,handler_set> Base;
public:
	server(int max_handler_count):Base((max_handler_count+handler_set::GetMaxSocketCount()-1)/handler_set::GetMaxSocketCount())
	{
		
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	server::Init();

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
	//worker::Configure(&tls_ctx_config);
#endif

	//mgr.Start("./ssl/dev_nopass.key","./ssl/dev.crt");

	auto s = std::make_shared<server>();
	s->Start();

	getchar();

	//mgr.Stop();

	s->Stop();
	s.reset();

	server::Term();

	return 0;
}


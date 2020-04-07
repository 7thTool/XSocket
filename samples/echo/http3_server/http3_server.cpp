// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttp3ServerImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class manager;
class server;

typedef TaskSocketServiceT<ThreadCVService> handler_service;
class handler : public Http3Handler<handler,manager,server,CVSocketT<handler_service,SocketEx>>
{
	typedef Http3Handler<handler,manager,server,CVSocketT<handler_service,SocketEx>> Base;
public:
	handler(manager *mgr, server *ep, SSL_CTX *ssl_ctx, const ngtcp2_cid *rcid):Base(mgr,ep,ssl_ctx,rcid)
	{
		
	}
};
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{

};
class manager : public QuicHttp3ManagerT<manager,server,handler_set>
{
	typedef QuicHttp3ManagerT<manager,server,handler_set> Base;
public:
	manager(int max_handler_count):Base((max_handler_count+handler_set::GetMaxSocketCount()-1)/handler_set::GetMaxSocketCount())
	{
		this->tx_loss_prob = 0.;
		this->rx_loss_prob = 0.;
		this->ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
						"POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
		this->groups = "P-256:X25519:P-384:P-521";
		this->timeout = 30 * NGTCP2_SECONDS;
		{
			auto path = realpath(".", nullptr);
			assert(path);
			this->docs = path;
			free(path);
		}
		this->mime_types_file = "/etc/mime.types";
		this->max_data = 1_m;
		this->max_stream_data_bidi_local = 256_k;
		this->max_stream_data_bidi_remote = 256_k;
		this->max_stream_data_uni = 256_k;
		this->max_streams_bidi = 100;
		this->max_streams_uni = 3;
		this->max_dyn_length = 20_m;

		if (generate_secret(this->static_secret.data(),
									this->static_secret.size()) != 0) {
			std::cerr << "Unable to generate static secret" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
};

typedef TaskSocketServiceT<ThreadService> udp_socket_service;
typedef QuickSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;
class server : public SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>>
{
	typedef SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>> Base;
public:

	bool Start()
	{
		Base::Start();
		return true;
	}

protected:
	//
	virtual bool OnInit()
	{
		bool ret = Base::OnInit();
		if(!ret) {
			return false;
		}
		Open(AF_INETType,SOCK_DGRAM,0);
		SetSockOpt(SOL_SOCKET, SO_REUSEADDR, 1);
		SockAddrType stAddr = {0};
	#ifdef USE_IPV6
		stAddr.sin6_family = AF_INET6;
		IpStr2IpAddr(DEFAULT_IP,AF_INET6,&stAddr.sin6_addr);
		stAddr.sin6_port = htons((u_short)DEFAULT_PORT);
	#else
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = Ip2N(Url2Ip(DEFAULT_IP));
		stAddr.sin_port = htons((u_short)DEFAULT_PORT);
	#endif//
		Bind((const SOCKADDR*)&stAddr, sizeof(stAddr));
		Select(FD_READ);
		SetNonBlock();//设为非阻塞模式
		return true;
	}

	virtual void OnTerm()
	{
		//服务结束运行，释放资源
		if(Base::IsSocket()) {
#ifndef WIN32
			Base::ShutDown();
#endif
			Base::Trigger(FD_CLOSE, 0);
		}
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	Socket::Init();

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

	manager mgr(DEFAULT_MAX_FD_SETSIZE);
	mgr.Start("./ssl/dev_nopass.key","./ssl/dev.crt");

	server *s = new server();
	s->Start();

	getchar();

	mgr.Stop();

	s->Stop();
	delete s;

	Socket::Term();

	return 0;
}


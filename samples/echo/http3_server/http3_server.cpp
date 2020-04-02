// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttp3Impl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

typedef TaskSocketServiceT<ThreadService> udp_socket_service;
typedef TaskSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;

class manager;
class server;

class handler : public Http3Handler<handler,manager,server,CVSocketT<ThreadCVService,SocketEx>>
{
public:
	//
};

typedef TaskSocketServiceT<ThreadCVService> handler_service;
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{

};
typedef SocketManagerT<handler_set> handler_manager;

class manager : public QuicServerManagerT<manager,server,handler>
{

};

class server : public SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>>
{
	typedef SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>> Base;
protected:
	std::string addr_;
	u_short port_;
public:

	bool Start(const char* address, u_short port)
	{
		addr_ = address;
		port_ = port;
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
		if(port_ <= 0) {
			return false;
		}
		Open(AF_INETType,SOCK_DGRAM);
		SetSockOpt(SOL_SOCKET, SO_REUSEADDR, 1);
		SockAddrType stAddr = {0};
	#ifdef USE_IPV6
		stAddr.sin6_family = AF_INET6;
		IpStr2IpAddr(addr_.c_str(),AF_INET6,&stAddr.sin6_addr);
		stAddr.sin6_port = htons((u_short)port_);
	#else
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = Ip2N(Url2Ip(addr_.c_str()));
		stAddr.sin_port = htons((u_short)port_);
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

	handler_manager mgr(DEFAULT_MAX_FD_SETSIZE);
	mgr.Start();

	server *s = new server();
	s->Start(DEFAULT_IP, DEFAULT_PORT);

	getchar();

	mgr.Stop();

	s->Stop();
	delete s;

	Socket::Term();

	return 0;
}


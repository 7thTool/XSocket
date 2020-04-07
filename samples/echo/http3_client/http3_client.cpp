// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttp3ClientImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class manager;
class client;

typedef TaskSocketServiceT<ThreadCVService> handler_service;
class handler : public Http3ClientHandler<handler,manager,client,CVSocketT<handler_service,SocketEx>>
{
public:
	//
};
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{

};
class manager : public Http3ClientManagerT<manager,client,handler_set>
{
	typedef Http3ClientManagerT<manager,client,handler_set> Base;
public:
	manager(int max_handler_count):Base((max_handler_count+handler_set::GetMaxSocketCount()-1)/handler_set::GetMaxSocketCount())
	{
  this->tx_loss_prob = 0.;
  this->rx_loss_prob = 0.;
  this->fd = -1;
  this->ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
                   "POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
  this->groups = "P-256:X25519:P-384:P-521";
  this->nstreams = 0;
  this->data = nullptr;
  this->datalen = 0;
  this->version = NGTCP2_PROTO_VER;
  this->timeout = 30 * NGTCP2_SECONDS;
  this->http_method = "GET";
  this->max_data = 1_m;
  this->max_stream_data_bidi_local = 256_k;
  this->max_stream_data_bidi_remote = 256_k;
  this->max_stream_data_uni = 256_k;
  this->max_streams_bidi = 1;
  this->max_streams_uni = 100;

  if (generate_secret(this->static_secret.data(),
                            this->static_secret.size()) != 0) {
    std::cerr << "Unable to generate static secret" << std::endl;
    exit(EXIT_FAILURE);
  }
	}
};

typedef TaskSocketServiceT<ThreadService> udp_socket_service;
typedef TaskSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;
class client : public SocketExImpl<client,SelectUdpClientT<udp_socket_service,udp_socket>>
{
	typedef SocketExImpl<client,SelectUdpClientT<udp_socket_service,udp_socket>> Base;
public:

protected:
	//
	virtual bool OnInit()
	{
		bool ret = Base::OnInit();
		if(!ret) {
			return false;
		}
		Open(AF_INETType,SOCK_DGRAM,0);
		SetNonBlock();//设为非阻塞模式
		Select(FD_READ);
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
		SendBuf("hello", 5, (const SOCKADDR*)&stAddr, sizeof(SockAddrType));
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

	manager mgr(DEFAULT_FD_SETSIZE);
	mgr.Start("./ssl/dev_nopass.key","./ssl/dev.crt");

	client *s = new client();
	s->Start();

	getchar();

	mgr.Stop();

	s->Stop();
	delete s;

	Socket::Term();

	return 0;
}


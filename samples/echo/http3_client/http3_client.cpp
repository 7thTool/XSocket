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

typedef TaskSocketServiceT<ThreadService> udp_socket_service;
typedef TaskSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;

class manager;
class server;

class handler : public Http3ClientHandler<handler,manager,server,CVSocketT<ThreadCVService,SocketEx>>
{
public:
	//
};

typedef TaskSocketServiceT<ThreadCVService> handler_service;
class handler_set : public SocketSetT<handler_service,handler,DEFAULT_FD_SETSIZE>
{

};
typedef SocketManagerT<handler_set> handler_manager;

class manager : public QuicClientManagerT<manager,server,handler>
{

};

class client : public SocketExImpl<server,SelectUdpClientT<udp_socket_service,udp_socket>>
{
	typedef SocketExImpl<server,SelectUdpClientT<udp_socket_service,udp_socket>> Base;
public:

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

	handler_manager mgr(DEFAULT_FD_SETSIZE);
	mgr.Start();

	client *s = new client();
	s->Start();

	getchar();

	mgr.Stop();

	s->Stop();
	delete s;

	Socket::Term();

	return 0;
}


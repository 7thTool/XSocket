#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttpImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#endif//

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

class Event
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
typedef XSocket::DelayEventServiceT<Event,XSocket::ThreadService> ClientService;

class client
#ifndef USE_MANAGER
	: public XSocket::SocketExImpl<client,XSocket::SelectClientT<ClientService,XSocket::HttpSocketT<XSocket::SimpleSocketT<XSocket::ConnectSocketT<XSocket::SocketEx>>>>>
#else
	: public SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > >
#endif//USE_MANAGER
{
#ifndef USE_MANAGER
	typedef XSocket::SocketExImpl<client,XSocket::SelectClientT<ClientService,XSocket::HttpSocketT<XSocket::SimpleSocketT<XSocket::ConnectSocketT<XSocket::SocketEx>>>>> Base;
#else
	typedef SocketExT<client,SimpleSocketArchitectureT<ProxyConnectHandler<SimpleSocketArchitecture<ConnectSocketT<SocketEx> > > > > Base;
#endif//USE_MANAGER
protected:
	//std::once_flag start_flag_;
	std::string addr_;
	u_short port_;
public:
	client()
	{
		
	}

#ifndef USE_MANAGER
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
		Connect(addr_.c_str(), port_);

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
#endif//USE_MANAGER

public:
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}

protected:
	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.flags);
		}
	}

protected:
	//
	virtual void OnMessage(const XSocket::HttpRequest& req)
	{
		PRINTF("%79s\n", req.body_.first);
	}

#ifdef USE_WEBSOCKET
	virtual void OnUpgrade()
	{
		SendWebSocketBuf("hello.", 6, WS_OP_TEXT|WS_FINAL_FRAME);
	}
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{
		PRINTF("%-79s\n", lpBuf);
		SendWebSocketBuf("hello.", 6, WS_FINAL_FRAME|WS_OP_TEXT);
	}
#endif

	virtual void OnConnect(int nErrorCode)
	{
		Base::OnConnect(nErrorCode);
		if(!IsConnected()) {
			return;
		}
#ifdef USE_WEBSOCKET
		Upgrade("localhost");
#else
		PRINTF("%s\n",http_get_raw.c_str());
		SendBuf(http_get_raw.c_str(),http_get_raw.size(),0);
#endif
	}
};

#ifdef USE_MANAGER
#ifdef USE_EPOLL
class manager : public EPollManagerT<client,DEFAULT_FD_SETSIZE>
#else
class manager : public SelectManagerT<client,DEFAULT_FD_SETSIZE>
#endif//
#else
class manager : public XSocket::ThreadService
#endif//
{
protected:
	client *c;
public:

#ifdef USE_MANAGER
	manager(int nMaxSocketCount):Base(nMaxSocketCount)
#else
	manager(int nMaxSocketCount)
#endif
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
	#ifndef USE_MANAGER
			c[i].Start(DEFAULT_IP,DEFAULT_PORT);
	#else
			c[i].Open();
			AddSocket(&c[i]);
			c[i].Connect(DEFAULT_IP,DEFAULT_PORT);
	#endif//
		}
		return true;
	}

	virtual void OnTerm()
	{
	#ifdef USE_MANAGER
		Base::OnTerm();
		RemoveAllSocket(true);
	#else
		for(int i=0;i<DEFAULT_CLIENT_COUNT;i++)
		{
			c[i].Stop();
		}
	#endif//
		delete []c;
	}
};

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	XSocket::InitNetEnv();
	
	manager m(DEFAULT_CLIENT_COUNT);
	m.Start();
	getchar();
	m.Stop();

	XSocket::ReleaseNetEnv();
	return 0;
}


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
using namespace XSocket;

class worker;

class Event
{
public:
	worker* dst = nullptr;
	int id;
	std::string buf;
	int flags;

	Event() {}
	Event(worker* d, int id, const char* buf, int len, int flag):dst(d),id(id),buf(buf,len),flags(flag){}

	// inline int get_id() { return evt; }
	// inline const char* get_data() { return data.c_str(); }
	// inline int get_datalen() { return data.size(); }
	// inline int get_flags() { return flags; }
};
typedef SimpleEventServiceT<DelayEventServiceT<Event,ThreadService>> WorkService;
//typedef ThreadService WorkService;

#ifdef USE_EPOLL
typedef EPollSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#elif defined(USE_IOCP)
typedef CompletionPortSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#else
typedef SelectSocketSetT<WorkService,worker,DEFAULT_FD_SETSIZE> WorkSocketSet;
#endif//

class worker
#ifdef USE_EPOLL
	: public SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<EPollSocketT<WorkSocketSet,SocketEx>>>>>>
#elif defined(USE_IOCP)
	: public SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<CompletionPortSocketT<WorkSocketSet,SocketEx>>>>>>
#else
	: public SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<SelectSocketT<WorkSocketSet,SocketEx>>>>>>
#endif
{
#ifdef USE_EPOLL
	typedef SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<EPollSocketT<WorkSocketSet,SocketEx>>>>>> Base;
#elif defined(USE_IOCP)
	typedef SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<CompletionPortSocketT<WorkSocketSet,SocketEx>>>>>> Base;
#else
	typedef SocketExImpl<worker,HttpSocketT<SimpleEvtSocketT<SimpleSocketT<WorkSocketT<SelectSocketT<WorkSocketSet,SocketEx>>>>>> Base;
#endif
public:
	worker()
	{
		
	}

	~worker() 
	{
		
	}

public:
	inline void PostBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		Post(Event(this,FD_WRITE,lpBuf,nBufLen,nFlags));
	}

	virtual void OnEvent(const Event& evt)
	{
		if(evt.id == FD_WRITE) {
			SendBuf(evt.buf.c_str(),evt.buf.size(),evt.flags);
		}
	}
protected:
	//
	virtual void OnMessage(const HttpRequest& req)
	{
		PRINTF("%79s\n", req.body_.first);
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
	: public SelectServerT<ThreadService,SocketExImpl<server,ListenSocketT<SocketEx>>,WorkSocketSet>
{
	typedef SelectServerT<ThreadService,SocketExImpl<server,ListenSocketT<SocketEx>>,WorkSocketSet> Base;
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
			printf("server worker count is [%d]\n", GetSocketCount());
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
	Socket::Init();

	server *s = new server();
	s->Start(DEFAULT_IP, DEFAULT_PORT);
	getchar();
	s->Stop();
	delete s;

	Socket::Term();

	return 0;
}


// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttp3ClientImpl.h"
#if USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif USE_IOCP
#include "../../../XSocket/XCompletionPort.h"
#endif//
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class manager;
class client;

typedef TaskServiceT<ThreadService> udp_socket_service;
typedef QuickSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;
class client : public SocketExImpl<client,SelectUdpClientT<udp_socket_service,udp_socket>>
, public std::enable_shared_from_this<client>
{
	typedef SocketExImpl<client,SelectUdpClientT<udp_socket_service,udp_socket>> Base;
public:
	//using udp_socket::Buffer;

	inline void Post(std::function<void()> && task)
	{
		udp_socket_service::Post(0, this, std::move(task));
	}

	// template<class F, class... Args>
	// inline auto PostF(F&& f, Args&&... args)
	// 	-> std::future<typename std::result_of<F(Args...)>::type>
	// {
	// 	return udp_socket_service::PostDelayF(0, this, std::forward<F>(f), std::forward<Args>(args)...);
	// }

protected:
	//
	virtual bool OnStart();
	virtual void OnStop();
  	virtual void OnRecvBuf(Buffer& buf);
};

typedef TaskServiceT<ThreadCVService> handler_service;
class handler : public Http3ClientHandler<handler,manager,client,CVSocketT<handler_service,SocketEx>>
{
	typedef Http3ClientHandler<handler,manager,client,CVSocketT<handler_service,SocketEx>> Base;
public:
	handler(manager *mgr, std::shared_ptr<client> ep, SSL_CTX *ssl_ctx):Base(mgr,ep,ssl_ctx)
	{
		
	}

  int init(std::shared_ptr<client> ep, const Address &remote_addr, const std::string &host, u_short port) {
	  int ret = Base::init(ep, remote_addr, host, port);
  	//   client::Buffer buf("hello", 5, (const SOCKADDR*)&remote_addr.su, remote_addr.len);
	//   ep->PostF([ep,remote_addr,buf=std::move(buf)]()mutable{
	// 	  std::cout << buf.data() << std::endl;
	// 	  ep->SendBuf(std::move(buf));
	// 	});
	  return ret;
  }

int write_streams() {
  std::array<nghttp3_vec, 16> vec;
  PathStorage path;
  size_t pktcnt = 0;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize sveccnt = 0;

    if (httpconn_ && ngtcp2_conn_get_max_data_left(conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                  << std::endl;
        last_error_ = quic_err_app(sveccnt);
        disconnect();
        return -1;
      }
    }

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    auto nwrite = ngtcp2_conn_writev_stream(
        conn_, &path.path, sendbuf_.wpos(), max_pktlen_, &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, timestamp());
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
	  {
        assert(ndatalen == -1);
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED &&
            ngtcp2_conn_get_max_data_left(conn_) == 0) {
          return 0;
        }

		auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
        }
        continue;
	  }
      case NGTCP2_ERR_WRITE_STREAM_MORE:
	  {
        assert(ndatalen > 0);
		auto rv = nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
        }
        continue;
	  }
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      last_error_ = quic_err_transport(nwrite);
      disconnect();
      return -1;
    }

    if (nwrite == 0) {
      // We are congestion limited.
      return 0;
    }

    sendbuf_.push(nwrite);

    this->update_remote_addr(&path.path.remote);
    reset_idle_timer();

	auto rv = send_packet();
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }

    // if (++pktcnt == 10) {
    //   ev_io_start(loop_, &wev_);
    //   return 0;
    // }
  }
}

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

manager mgr(DEFAULT_FD_SETSIZE);


	bool client::OnStart()
	{
		bool ret = Base::OnStart();
		if(!ret) {
			return false;
		}
		Open(AF_INETType,SOCK_DGRAM,0);
		SetNonBlock();//设为非阻塞模式
		Select(FD_READ);
		Address remote_addr;
		remote_addr.len = sizeof(SockAddrType);
		SockAddrType stAddr = {0};
	#if USE_IPV6
		stAddr.sin6_family = AF_INET6;
		IpStr2IpAddr(DEFAULT_IP,AF_INET6,&stAddr.sin6_addr);
		stAddr.sin6_port = htons((u_short)8083);
		remote_addr.su.in6 = stAddr;
	#else
		stAddr.sin_family = AF_INET;
		stAddr.sin_addr.s_addr = Ip2N(Url2Ip("127.0.0.1"));
		stAddr.sin_port = htons((u_short)8083);
		remote_addr.su.in = stAddr;
	#endif//
		mgr.AddConnect(shared_from_this(), remote_addr, "127.0.0.1", 8083);
		return true;
	}

	void client::OnStop()
	{
		//服务结束运行，释放资源
		if(Base::IsSocket()) {
#ifndef WIN32
			Base::ShutDown();
#endif
			Base::Trigger(FD_CLOSE, 0);
		}
		Base::OnStop();
	}

  	void client::OnRecvBuf(Buffer& buf)
	{
		mgr.OnRecvBuf(shared_from_this(), buf);
	}

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	UdpBufferPool::Inst().Init(1024);

	Socket::Init();

	mgr.Start();

	auto s = std::make_shared<client>();
	s->Start();

	getchar();

	mgr.Stop();

	s->Stop();
	s.reset();

	Socket::Term();

	return 0;
}


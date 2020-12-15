// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XHttp3ServerImpl.h"
#if USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif USE_IOCP
#include "../../../XSocket/XCompletionPort.h"
#endif//
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

class manager;
class server;

typedef TaskServiceT<ThreadService> udp_socket_service;
typedef QuickSocketT<SimpleUdpSocketExT<SelectSocketT<udp_socket_service,SocketEx>>> udp_socket;
class server : public SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>>
, public std::enable_shared_from_this<server>
{
	typedef SocketExImpl<server,SelectUdpServerT<udp_socket_service,udp_socket>> Base;
public:

	bool Start()
	{
		Base::Start();
		return true;
	}

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
class handler : public Http3Handler<handler,manager,server,CVSocketT<handler_service,SocketEx>>
{
	typedef Http3Handler<handler,manager,server,CVSocketT<handler_service,SocketEx>> Base;
public:
	handler(manager *mgr, std::shared_ptr<server> ep, SSL_CTX *ssl_ctx, const ngtcp2_cid *rcid):Base(mgr,ep,ssl_ctx,rcid)
	{
		
	}

int write_streams() { 
  auto ep = this->sock_ptr_;
  const sockaddr *sa = &this->remote_addr_.su.sa;
  socklen_t salen = this->remote_addr_.len;
  std::array<nghttp3_vec, 16> vec;
  PathStorage path;

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
        return handle_error();
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
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED && ngtcp2_conn_get_max_data_left(conn_) == 0) {
          return 0;
        }

		auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);  
        if (rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          return handle_error();
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
          return handle_error();
        }
        continue;
	  }
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_writev_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      last_error_ = quic_err_transport(nwrite);
      return handle_error();
    }

    if (nwrite == 0) {
      // We are congestion limited.
      return 0;
    }

    sendbuf_.push(nwrite);

    //update_endpoint(&path.path.local);
    update_remote_addr(&path.path.remote);
    reset_idle_timer();

    send_packet();
  }
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

	manager mgr(DEFAULT_MAX_FD_SETSIZE);

	bool server::OnStart()
	{
		bool ret = Base::OnStart();
		if(!ret) {
			return false;
		}
		Open(AF_INETType,SOCK_DGRAM,0);
		SetSockOpt(SOL_SOCKET, SO_REUSEADDR, 1);
		SockAddrType stAddr = {0};
	#if USE_IPV6
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

	void server::OnStop()
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

	void server::OnRecvBuf(Buffer& buf)
	{
		mgr.OnRecvBuf(shared_from_this(), buf);
	}

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	UdpBufferPool::Inst().Init(10240);

	Socket::Init();

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
    tls_ctx_config.prefer_server_ciphers;
	//worker::Configure(&tls_ctx_config);
#endif

	mgr.Start("./ssl/dev_nopass.key","./ssl/dev.crt");

	auto s = std::make_shared<server>();
	s->Start();

	getchar();

	mgr.Stop();

	s->Stop();
	s.reset();

	Socket::Term();

	return 0;
}


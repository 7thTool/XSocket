/*
 * Copyright: 7thTool Open Source <i7thTool@qq.com>
 * All rights reserved.
 * 
 * Author	: Scott
 * Email	：i7thTool@qq.com
 * Blog		: http://blog.csdn.net/zhangzq86
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _H_XQUIC_IMPL_H_
#define _H_XQUIC_IMPL_H_

#include "XSocketImpl.h"
#include "XCodec.h"
#include "XBuffer.h"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <array>
#include <vector>
#include <deque>
#include <map>
//#include <string_view>
#include <iostream>
#include <sstream>
#include <strstream>
#include <algorithm>
#include <limits>
#include <random>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
//using namespace ngtcp2;

//Quic 包的大小应该不大于MTU，以避免ip 分片。当前的Quic实现在ipv6环境每个包 最大限制为1350的字节，ipv4环境下为1370，这两个限制都不包含ip 和 udp 头。

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T> struct Defer {
  Defer(F &&f, T &&... t)
      : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = typename std::result_of<typename std::decay<F>::type(
      typename std::decay<T>::type...)>::type;
  std::function<ResultType()> f;
};

template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&... t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

template <typename T, size_t N> constexpr size_t array_size(T (&)[N]) {
  return N;
}

template <typename T, size_t N> constexpr size_t str_size(T (&)[N]) {
  return N - 1;
}

// User-defined literals for K, M, and G (powers of 1024)

constexpr unsigned long long operator"" _k(unsigned long long k) {
  return k * 1024;
}

constexpr unsigned long long operator"" _m(unsigned long long m) {
  return m * 1024 * 1024;
}

constexpr unsigned long long operator"" _g(unsigned long long g) {
  return g * 1024 * 1024 * 1024;
}

inline bool numeric_host(const char *hostname, int family) {
  int rv;
  std::array<uint8_t, sizeof(struct in6_addr)> dst;

  rv = inet_pton(family, hostname, dst.data());

  return rv == 1;
}

inline bool numeric_host(const char *hostname) {
  return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
}

inline ngtcp2_crypto_level from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level) {
  switch (ossl_level) {
  case ssl_encryption_initial:
    return NGTCP2_CRYPTO_LEVEL_INITIAL;
  case ssl_encryption_early_data:
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  case ssl_encryption_handshake:
    return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
  case ssl_encryption_application:
    return NGTCP2_CRYPTO_LEVEL_APP;
  default:
    assert(0);
  }
}

inline OSSL_ENCRYPTION_LEVEL from_ngtcp2_level(ngtcp2_crypto_level crypto_level) {
  switch (crypto_level) {
  case NGTCP2_CRYPTO_LEVEL_INITIAL:
    return ssl_encryption_initial;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    return ssl_encryption_handshake;
  case NGTCP2_CRYPTO_LEVEL_APP:
    return ssl_encryption_application;
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    return ssl_encryption_early_data;
  default:
    assert(0);
  }
}

namespace XSocket {

namespace {
constexpr size_t NGTCP2_SV_SCIDLEN = 18;
} // namespace

namespace {
constexpr size_t TOKEN_RAND_DATALEN = 16;
} // namespace

namespace {
constexpr size_t MAX_DYNBUFLEN = 1024 * 1024;
} // namespace

namespace {
auto randgen =  std::mt19937(/*std::random_device()*/);
} // namespace

enum network_error {
  NETWORK_ERR_OK = 0,
  NETWORK_ERR_FATAL = -10,
  NETWORK_ERR_SEND_BLOCKED = -11,
  NETWORK_ERR_CLOSE_WAIT = -12,
  NETWORK_ERR_RETRY = -13,
  NETWORK_ERR_DROP_CONN = -14,
};

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr sa;
  sockaddr_in6 in6;
  sockaddr_in in;
};

struct Address {
  socklen_t len;
  union sockaddr_union su;
};

template <class T, class TManager, class TSocket, class TBase>
class QuicHandlerBaseT : public ConnectionT<TSocket, TaskSocketT<TBase>>
{
  typedef QuicHandlerBaseT<T, TManager, TSocket, TBase> This;
  typedef ConnectionT<TSocket, TaskSocketT<TBase>> Base;

protected:
  TManager* manager_;
  Address remote_addr_;
  SSL_CTX *ssl_ctx_ ;
  SSL *ssl_;
  struct Buffer {
    Buffer(const uint8_t *data, size_t datalen);
    explicit Buffer(size_t datalen);

    size_t size() const { return tail - buf.data(); }
    size_t left() const { return buf.data() + buf.size() - tail; }
    uint8_t *const wpos() { return tail; }
    const uint8_t *rpos() const { return buf.data(); }
    void push(size_t len) { tail += len; }
    void reset() { tail = buf.data(); }

    std::vector<uint8_t> buf;
    // tail points to the position of the buffer where write should
    // occur.
    uint8_t *tail;
  };
  struct Crypto {
    /* data is unacknowledged data. */
    std::deque<Buffer> data;
    /* acked_offset is the size of acknowledged crypto data removed from
      |data| so far */
    uint64_t acked_offset;
  };
  Crypto crypto_[3];
  ngtcp2_conn *conn_;
 public:
	QuicHandlerBaseT(TManager* manager, TSocket *server, SSL_CTX *ssl_ctx):Base(server),manager_(manager),ssl_ctx_(ssl_ctx),ssl_(nullptr),crypto_{},conn_(nullptr)
	{
	}

	~QuicHandlerBaseT() 
	{
		if (IsDebug()) {
			std::cerr << "Closing QUIC connection" << std::endl;
		}

		if (conn_) {
			ngtcp2_conn_del(conn_);
            conn_ = nullptr;
		}

		if (ssl_) {
			SSL_free(ssl_);
            ssl_ = nullptr;
		}
	}

  TManager* manager() { return manager_; }
	
const Address &remote_addr() const { return remote_addr_; }

ngtcp2_conn *conn() const { return conn_; }

void write_handshake(ngtcp2_crypto_level level,
                                     const uint8_t *data, size_t datalen) {
  auto &crypto = crypto_[level];
  crypto.data.emplace_back(data, datalen);

  auto &buf = crypto.data.back();

  ngtcp2_conn_submit_crypto_data(conn_, level, buf.rpos(), buf.size());
}

int recv_crypto_data(ngtcp2_crypto_level crypto_level,
                              const uint8_t *data, size_t datalen) {
  return ngtcp2_crypto_read_write_crypto_data(conn_, ssl_, crypto_level, data,
                                              datalen);
}

int handshake_completed() {
  if (IsDebug()) {
    std::cerr << "Negotiated cipher suite is " << SSL_get_cipher_name(ssl_)
              << std::endl;

    const unsigned char *alpn = nullptr;
    unsigned int alpnlen;

    SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);
    if (alpn) {
      std::cerr << "Negotiated ALPN is ";
      std::cerr.write(reinterpret_cast<const char *>(alpn), alpnlen);
      std::cerr << std::endl;
    }
  }

  return 0;
}

int recv_stream_data(int64_t stream_id, uint8_t fin,
                              const uint8_t *data, size_t datalen) {
        // if (!config.quiet && !config.no_quic_dump) {
        //   debug::print_stream_data(stream_id, data, datalen);
        // }

  auto nconsumed = on_recv_stream_data(stream_id, fin, data, datalen);
  if (nconsumed < 0)
  {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed) << std::endl;
    //last_error_ = quic_err_app(nconsumed);
    return -1;
  }
            
  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

  return 0;
}

virtual int on_recv_stream_data(int64_t stream_id, uint8_t fin, const uint8_t *data, size_t datalen)
{
  return 0;
}

void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level,
                                    uint64_t offset, size_t datalen) {
  auto &crypto = crypto_[crypto_level];
  remove_tx_stream_data(crypto.data, crypto.acked_offset, offset + datalen);
}

size_t remove_tx_stream_data(std::deque<Buffer> &d, uint64_t &tx_offset,
                             uint64_t offset) {
  size_t len = 0;
  for (; !d.empty() && tx_offset + d.front().size() <= offset;) {
    auto &v = d.front();
    len += v.size();
    tx_offset += v.size();
    d.pop_front();
  }
  return len;
}

virtual int acked_stream_data_offset(int64_t stream_id, size_t datalen) {
  return 0;
}

void on_stream_open(int64_t stream_id) {
  if (!ngtcp2_is_bidi_stream(stream_id)) {
    return;
  }
  // auto it = streams_.find(stream_id);
  // assert(it == std::end(streams_));
  // streams_.emplace(stream_id, std::make_unique<Stream>(stream_id, this));
}

virtual int on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  return 0;
}

virtual void extend_max_remote_streams_bidi(uint64_t max_streams) {
  
}

virtual int extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  return 0;
}

virtual int on_stream_reset(int64_t stream_id) {
  return 0;
}

int rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx)
{
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
}

int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen)
{
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  auto f = [&dis]() { return dis(randgen); };

  std::generate_n(cid->data, cidlen, f);
  cid->datalen = cidlen;
  auto md = ngtcp2_crypto_md{const_cast<EVP_MD *>(EVP_sha256())};
  if (ngtcp2_crypto_generate_stateless_reset_token(
          token, &md, manager_->static_secret.data(), manager_->static_secret.size(),
          cid) != 0)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  server()->associate_cid(cid, this);

  return 0;
}
//,
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid)
{
  server()->dissociate_cid(cid);
  return 0;
}

void signal_write() {  }

  int on_read(const sockaddr *sa, socklen_t salen, uint8_t *data, size_t datalen)
{
	return 0;
}

  int on_write()
  {
	  return 0;
  }

  
int send_conn_close() {
  if (IsDebug()) {
    std::cerr << "Closing Period: TX CONNECTION_CLOSE" << std::endl;
  }
/*
  assert(conn_closebuf_ && conn_closebuf_->size());

  if (sendbuf_.size() == 0) {
    std::copy_n(conn_closebuf_->rpos(), conn_closebuf_->size(),
                sendbuf_.wpos());
    sendbuf_.push(conn_closebuf_->size());
  }

  return server_->send_packet(*endpoint_, remote_addr_, sendbuf_.rpos(),
                              sendbuf_.size(), 0, &wev_);*/
  return 0;
}

};

template <class T, class THandler>
class QuicManagerBaseT
{
    typedef THandler Handler;
protected:
  SSL_CTX *ssl_ctx_;
  // session_file is a path to a file to write, and read TLS session.
  //const char *session_file;

    int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                             unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg)
    {
        auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
        const uint8_t *alpn;
        size_t alpnlen;
        auto version = ngtcp2_conn_get_negotiated_version(h->conn());

        switch (version)
        {
        case NGTCP2_PROTO_VER:
            alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_H3);
            alpnlen = str_size(NGTCP2_ALPN_H3);
            break;
        default:
            if (IsDebug())
            {
                std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                          << version << std::dec << std::endl;
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1)
        {
            if (std::equal(alpn, alpn + alpnlen, p))
            {
                *out = p + 1;
                *outlen = *p;
                return SSL_TLSEXT_ERR_OK;
            }
        }

        if (IsDebug())
        {
            std::cerr << "Client did not present ALPN " << &NGTCP2_ALPN_H3[1]
                      << std::endl;
        }

        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    SSL_QUIC_METHOD quic_method = SSL_QUIC_METHOD{
        //set_encryption_secrets
        [](SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
           const uint8_t *read_secret,
           const uint8_t *write_secret, size_t secret_len) {
            auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
            auto rv = h->on_key(from_ossl_level(ossl_level), read_secret,write_secret, secret_len);
            if (rv != 0) {
                return 0;
            }
            return 1;
        },
        //add_handshake_data
        [](SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
           const uint8_t *data, size_t len) {
            auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
            h->write_handshake(from_ossl_level(ossl_level), data, len);
            return 1;
        },
        //flush_flight
        [](SSL *ssl) { return 1; },
        //send_alert
        [](SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
            auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
            h->set_tls_alert(alert);
            return 1;
        },
    };

    SSL_CTX *create_server_ctx(const char *private_key_file, const char *cert_file)
    {
        constexpr static unsigned char sid_ctx[] = "ngtcp2 server";

        auto ssl_ctx = SSL_CTX_new(TLS_server_method());

        constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                                  SSL_OP_SINGLE_ECDH_USE |
                                  SSL_OP_CIPHER_SERVER_PREFERENCE |
                                  SSL_OP_NO_ANTI_REPLAY;

        SSL_CTX_set_options(ssl_ctx, ssl_opts);

        if (SSL_CTX_set_ciphersuites(ssl_ctx, this->ciphers) != 1)
        {
            std::cerr << "SSL_CTX_set_ciphersuites: "
                      << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_set1_groups_list(ssl_ctx, this->groups) != 1)
        {
            std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

        SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, nullptr);

        SSL_CTX_set_default_verify_paths(ssl_ctx);

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file,
                                        SSL_FILETYPE_PEM) != 1)
        {
            std::cerr << "SSL_CTX_use_PrivateKey_file: "
                      << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1)
        {
            std::cerr << "SSL_CTX_use_certificate_file: "
                      << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_check_private_key(ssl_ctx) != 1)
        {
            std::cerr << "SSL_CTX_check_private_key: "
                      << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);

        if (this->verify_client)
        {
            SSL_CTX_set_verify(ssl_ctx,
                               SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               //int verify_cb
                               [](int preverify_ok, X509_STORE_CTX *ctx) {
                                   // We don't verify the client certificate.  Just request it for the
                                   // testing purpose.
                                   return 1;
                               });
        }

        SSL_CTX_set_max_early_data(ssl_ctx, std::numeric_limits<uint32_t>::max());
        SSL_CTX_set_quic_method(ssl_ctx, &quic_method);
        SSL_CTX_set_client_hello_cb(ssl_ctx,
                                    //int client_hello_cb
                                    [](SSL *ssl, int *al, void *arg) {
                                        const uint8_t *tp;
                                        size_t tplen;

                                        if (!SSL_client_hello_get0_ext(ssl, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
                                                                       &tp, &tplen))
                                        {
                                            *al = SSL_AD_INTERNAL_ERROR;
                                            return SSL_CLIENT_HELLO_ERROR;
                                        }

                                        return SSL_CLIENT_HELLO_SUCCESS;
                                    },
                                    nullptr);

        return ssl_ctx;
    }
SSL_CTX *create_client_ctx(const char *private_key_file, const char *cert_file) {
  auto ssl_ctx = SSL_CTX_new(TLS_client_method());

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if (SSL_CTX_set_ciphersuites(ssl_ctx, this->ciphers) != 1) {
    std::cerr << "SSL_CTX_set_ciphersuites: "
              << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx, this->groups) != 1) {
    std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (private_key_file && cert_file) {
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file,
                                    SSL_FILETYPE_PEM) != 1) {
      std::cerr << "SSL_CTX_use_PrivateKey_file: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
      std::cerr << "SSL_CTX_use_certificate_file: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  SSL_CTX_set_quic_method(ssl_ctx, &quic_method);

  /*if (this->session_file)
  {
      SSL_CTX_set_session_cache_mode(
          ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
      SSL_CTX_sess_set_new_cb(ssl_ctx,
                              //int new_session_cb
                              [](SSL *ssl, SSL_SESSION *session) {
                                  if (SSL_SESSION_get_max_early_data(session) !=
                                      std::numeric_limits<uint32_t>::max())
                                  {
                                      std::cerr << "max_early_data_size is not 0xffffffff" << std::endl;
                                  }
                                  auto f = BIO_new_file(config.session_file, "w");
                                  if (f == nullptr)
                                  {
                                      std::cerr << "Could not write TLS session in " << config.session_file
                                                << std::endl;
                                      return 0;
                                  }

                                  PEM_write_bio_SSL_SESSION(f, session);
                                  BIO_free(f);

                                  return 0;
                              });
  }*/

  return ssl_ctx;
}

public:
	QuicManagerBaseT(const char *private_key_file, const char *cert_file)
	{
        T* pT = static_cast<T*>(this);
	    ssl_ctx_ = pT->IsServer()?create_server_ctx(private_key_file, cert_file):create_client_ctx(private_key_file, cert_file);
	}

	~QuicManagerBaseT() 
	{
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
	}

    inline bool IsServer() { return true; }
    inline bool IsDebug() { return true; }

public:
  // tx_loss_prob is probability of losing outgoing packet.
  double tx_loss_prob;
  // rx_loss_prob is probability of losing incoming packet.
  double rx_loss_probrx_loss_prob;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // version is a QUIC version to use.
  uint32_t version;
  // timeout is an idle timeout for QUIC connection.
  ngtcp2_duration timeout;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump;
  // max_data is the initial connection-level flow control window.
  uint64_t max_data;
  // max_stream_data_bidi_local is the initial stream-level flow
  // control window for a bidirectional stream that the local endpoint
  // initiates.
  uint64_t max_stream_data_bidi_local;
  // max_stream_data_bidi_remote is the initial stream-level flow
  // control window for a bidirectional stream that the remote
  // endpoint initiates.
  uint64_t max_stream_data_bidi_remote;
  // max_stream_data_uni is the initial stream-level flow control
  // window for a unidirectional stream.
  uint64_t max_stream_data_uni;
  // max_streams_bidi is the number of the concurrent bidirectional
  // streams.
  uint64_t max_streams_bidi;
  // max_streams_uni is the number of the concurrent unidirectional
  // streams.
  uint64_t max_streams_uni;
  // static_secret is used to derive keying materials for Stateless
  // Retry token.
  std::array<uint8_t, 32> static_secret;
};

/*!
 *	@brief QuickSocketT 定义.
 *
 *	封装QuickSocketT，实现Udp Quick收发数据功能
 */
template<class TBase>
class QuickSocketT : public TaskSocketT<TBase>
{
	typedef QuickSocketT<TBase> This;
	typedef TaskSocketT<TBase> Base;
public:
	QuickSocketT()
	{
			
	}

	~QuickSocketT() 
	{
		
	}
};

}

#endif//_H_XQUIC_IMPL_H_
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

#include "XBuffer.h"
#include "XCodec.h"
#include "XSocketImpl.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif  // HAVE_CONFIG_H

#include <array>
#include <deque>
#include <map>
#include <vector>
//#include <string_view>
#include <algorithm>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <strstream>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
// using namespace ngtcp2;

// Quic 包的大小应该不大于MTU，以避免ip 分片。当前的Quic实现在ipv6环境每个包
// 最大限制为1350的字节，ipv4环境下为1370，这两个限制都不包含ip 和 udp 头。

//tx是发送(transport),rx是接收(receive)

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T>
struct Defer {
  Defer(F &&f, T &&... t)
      : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = typename std::result_of<typename std::decay<F>::type(
      typename std::decay<T>::type...)>::type;
  std::function<ResultType()> f;
};

template <typename F, typename... T>
Defer<F, T...> defer(F &&f, T &&... t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

template <typename T, size_t N>
constexpr size_t array_size(T (&)[N]) {
  return N;
}

template <typename T, size_t N>
constexpr size_t str_size(T (&)[N]) {
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

inline OSSL_ENCRYPTION_LEVEL from_ngtcp2_level(
    ngtcp2_crypto_level crypto_level) {
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
}  // namespace

namespace {
constexpr size_t TOKEN_RAND_DATALEN = 16;
}  // namespace

namespace {
constexpr size_t MAX_DYNBUFLEN = 1024 * 1024;
}  // namespace

namespace {
auto randgen = std::mt19937(/*std::random_device()*/);
}  // namespace

inline int generate_secret(uint8_t *secret, size_t secretlen) {
  std::array<uint8_t, 16> rand;
  std::array<uint8_t, 32> md;

  assert(md.size() == secretlen);

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate_n(rand.data(), rand.size(), [&dis]() { return dis(randgen); });

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return -1;
  }

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  unsigned int mdlen = md.size();
  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
      !EVP_DigestUpdate(ctx, rand.data(), rand.size()) ||
      !EVP_DigestFinal_ex(ctx, md.data(), &mdlen)) {
    return -1;
  }

  std::copy_n(std::begin(md), secretlen, secret);
  return 0;
}

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

struct PathStorage {
  PathStorage() {
    path.local.addr = local_addrbuf.data();
    path.remote.addr = remote_addrbuf.data();
  }

  ngtcp2_path path;
  std::array<uint8_t, sizeof(sockaddr_storage)> local_addrbuf;
  std::array<uint8_t, sizeof(sockaddr_storage)> remote_addrbuf;
};

enum class QUICErrorType {
  Application,
  Transport,
  TransportVersionNegotiation,
};

struct QUICError {
  QUICError(QUICErrorType type, uint64_t code) : type(type), code(code) {}

  QUICErrorType type;
  uint64_t code;
};

inline QUICError quic_err_transport(int liberr) {
  if (liberr == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return {QUICErrorType::TransportVersionNegotiation, 0};
  }
  return {QUICErrorType::Transport,
          ngtcp2_err_infer_quic_transport_error_code(liberr)};
}

inline QUICError quic_err_tls(int alert) {
  return {QUICErrorType::Transport,
          static_cast<uint64_t>(NGTCP2_CRYPTO_ERROR | alert)};
}

inline ngtcp2_tstamp timestamp() {
  std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

template <class T, class TManager, class TSocket, class TBase>
class QuicHandlerBaseT : public ConnectionT<TSocket, TaskSocketT<TBase>> {
  typedef QuicHandlerBaseT<T, TManager, TSocket, TBase> This;
  typedef ConnectionT<TSocket, TaskSocketT<TBase>> Base;

 protected:
  TManager *manager_;
  Address remote_addr_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  size_t max_pktlen_;
  struct Buffer {
    Buffer(const uint8_t *data, size_t datalen): buf{data, data + datalen}, begin(buf.data()), tail(begin + datalen) {}
    explicit Buffer(size_t datalen): buf(datalen), begin(buf.data()), tail(begin) {}

  size_t size() const { return tail - begin; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return begin; }
  void push(size_t len) { tail += len; }
  void reset() { tail = begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
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
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  QUICError last_error_ = {QUICErrorType::Transport, 0};

 public:
  QuicHandlerBaseT(TManager *manager, TSocket *sock_ptr, SSL_CTX *ssl_ctx)
      : Base(sock_ptr),
        manager_(manager),
        ssl_ctx_(ssl_ctx),
        ssl_(nullptr),
        max_pktlen_(0),
        crypto_{},
        conn_(nullptr),
        sendbuf_{NGTCP2_MAX_PKTLEN_IPV4}
        //last_error_(QUICErrorType::Transport, 0) 
  {
    
  }

  ~QuicHandlerBaseT() {
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

  TManager *get_manager() { return manager_; }

  const Address &remote_addr() const { return remote_addr_; }

  ngtcp2_conn *get_conn() const { return conn_; }

void set_tls_alert(uint8_t alert) {
  last_error_ = quic_err_tls(alert);
}

  void write_handshake(ngtcp2_crypto_level level, const uint8_t *data,
                       size_t datalen) {
    auto &crypto = crypto_[level];
    crypto.data.emplace_back(data, datalen);

    auto &buf = crypto.data.back();

    ngtcp2_conn_submit_crypto_data(conn_, level, buf.rpos(), buf.size());
  }

  int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen) {
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

  int recv_stream_data(int64_t stream_id, uint8_t fin, const uint8_t *data,
                       size_t datalen) {
    // if (!config.quiet && !config.no_quic_dump) {
    //   debug::print_stream_data(stream_id, data, datalen);
    // }

    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn_, datalen);

    return 0;
  }

  void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level, uint64_t offset,
                             size_t datalen) {
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

  int acked_stream_data_offset(int64_t stream_id, size_t datalen) { return 0; }

  void on_stream_open(int64_t stream_id) {
    if (!ngtcp2_is_bidi_stream(stream_id)) {
      return;
    }
    // auto it = streams_.find(stream_id);
    // assert(it == std::end(streams_));
    // streams_.emplace(stream_id, std::make_unique<Stream>(stream_id, this));
  }

  int on_stream_close(int64_t stream_id, uint64_t app_error_code) { return 0; }

  void extend_max_remote_streams_bidi(uint64_t max_streams) {}

  int extend_max_stream_data(int64_t stream_id, uint64_t max_data) { return 0; }

  int on_stream_reset(int64_t stream_id) { return 0; }

  int rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
           ngtcp2_rand_ctx ctx) {
    auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
    std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
    return 0;
  }

  int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                            size_t cidlen) {
    auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
    auto f = [&dis]() { return dis(randgen); };

    std::generate_n(cid->data, cidlen, f);
    cid->datalen = cidlen;
    auto md = ngtcp2_crypto_md{const_cast<EVP_MD *>(EVP_sha256())};
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, &md, manager_->static_secret.data(),
            manager_->static_secret.size(), cid) != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    manager_->associate_cid(cid, this);

    return 0;
  }
  //,
  int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid) {
    manager_->dissociate_cid(cid);
    return 0;
  }

  void signal_write() {}

  int on_read(TSocket* ep, const sockaddr *sa, socklen_t salen, uint8_t *data,
              size_t datalen) {
    return 0;
  }

  int on_write() { return 0; }
};

template <class T, class TSocket, class THandlerSet>
class QuicManagerBaseT : public SocketManagerT<THandlerSet> {
  typedef SocketManagerT<THandlerSet> Base;
public:
  typedef THandlerSet HandlerSet;
	typedef typename Base::Socket Handler;

 protected:
  SSL_CTX *ssl_ctx_;
  // session_file is a path to a file to write, and read TLS session.
  // const char *session_file;

  SSL_QUIC_METHOD quic_method = SSL_QUIC_METHOD{
      // set_encryption_secrets
      [](SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level, const uint8_t *read_secret,
         const uint8_t *write_secret, size_t secret_len) {
        auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
        auto rv = h->on_key(from_ossl_level(ossl_level), read_secret,
                            write_secret, secret_len);
        if (rv != 0) {
          return 0;
        }
        return 1;
      },
      // add_handshake_data
      [](SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level, const uint8_t *data,
         size_t len) {
        auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
        h->write_handshake(from_ossl_level(ossl_level), data, len);
        return 1;
      },
      // flush_flight
      [](SSL *ssl) { return 1; },
      // send_alert
      [](SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
        auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
        h->set_tls_alert(alert);
        return 1;
      },
  };

 public:
  QuicManagerBaseT(int max_handlerset_count):Base(max_handlerset_count) {
    
  }

  ~QuicManagerBaseT() {
  }

	bool Start()
	{
    return Base::Start();
  }

  void Stop()
  {
    Base::Stop();

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
  double rx_loss_prob;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // nstreams is the number of streams to open.
  size_t nstreams;
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

  inline bool packet_lost(double prob) {
    auto p = std::uniform_real_distribution<>(0, 1)(randgen);
    return p < prob;
  }

  inline void associate_cid(const ngtcp2_cid *cid, Handler *h) {
    // ctos_.emplace(make_cid_key(cid), make_cid_key(h->scid()));
  }

  inline void dissociate_cid(const ngtcp2_cid *cid) {
    // tos_.erase(make_cid_key(cid));
  }

  int send_packet(TSocket *ep, const Address &remote_addr, const uint8_t *data,
                  size_t datalen, size_t gso_size = 0) {
    if (packet_lost(tx_loss_prob)) {
      if (IsDebug()) {
        std::cerr << "** Simulated outgoing packet loss **" << std::endl;
      }
      return NETWORK_ERR_OK;
    }

    ep->SendBuf((const char *)data, datalen,
                const_cast<sockaddr *>(&remote_addr.su.sa), remote_addr.len);

    return NETWORK_ERR_OK;
  }
};

/*!
 *	@brief QuickSocketT 定义.
 *
 *	封装QuickSocketT，实现Udp Quick收发数据功能
 */
template <class TBase>
class QuickSocketT : public TaskSocketT<TBase> {
  typedef QuickSocketT<TBase> This;
  typedef TaskSocketT<TBase> Base;

 public:
  Address addr_;

 public:
  QuickSocketT() {}

  ~QuickSocketT() {}

  SOCKET Open(int nSockAf, int nSockType, int nSockProtocol) {
    SOCKET sock = Base::Open(nSockAf, nSockType, nSockProtocol);
    if (sock != INVALID_SOCKET) {
      switch (nSockAf) {
        case AF_INET6:
          GetSockName((SOCKADDR*)&addr_.su.in6, &addr_.len);
          break;
        case AF_INET:
        default:
          GetSockName((SOCKADDR*)&addr_.su.in, &addr_.len);
          break;
      }
    }
    return sock;
  }
};

}  // namespace XSocket

#endif  //_H_XQUIC_IMPL_H_
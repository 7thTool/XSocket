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
#ifndef _H_XQUICK_IMPL_H_
#define _H_XQUICK_IMPL_H_

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
		}

		if (ssl_) {
			SSL_free(ssl_);
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

 template<class T, class TManager, class TSocket, class TBase>
 class QuicClientHandlerT : public QuicHandlerBaseT<T,TManager,TSocket,TBase>
 {
   typedef QuicClientHandlerT<T,TManager,TSocket,TBase> This;
   typedef QuicHandlerBaseT<T,TManager,TSocket,TBase> Base;
 protected:
  SSL *ssl_;
  Address local_addr_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  size_t max_pktlen_;
  uint32_t version_;
  // early_data_ is true if client attempts to do 0RTT data transfer.
  bool early_data_;

 public:
    
int init(int fd, const Address &local_addr, const Address &remote_addr,
                 const char *addr, const char *port, uint32_t version) {
  local_addr_ = local_addr;
  this->remote_addr_ = remote_addr;
  //fd_ = fd;
  addr_ = addr;
  port_ = port;
  version_ = version;

  switch (this->remote_addr_.su.storage.ss_family) {
  case AF_INET:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    return -1;
  }

  auto callbacks = ngtcp2_conn_callbacks{
//int client_initial
[](ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<T *>(user_data);

  if (c->recv_crypto_data(NGTCP2_CRYPTO_LEVEL_INITIAL, nullptr, 0) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      nullptr, // recv_client_initial
//int recv_crypto_data
[](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
//   if (!config.quiet && !config.no_quic_dump) {
//     debug::print_crypto_data(crypto_level, data, datalen);
//   }

  auto c = static_cast<T *>(user_data);

  if (c->recv_crypto_data(crypto_level, data, datalen) != 0) {
    auto err = ngtcp2_conn_get_tls_error(conn);
    if (err) {
      return err;
    }
    return NGTCP2_ERR_CRYPTO;
  }

  return 0;
},
      //int handshake_completed
      [](ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<T *>(user_data);

//   if (!config.quiet) {
//     debug::handshake_completed(conn, user_data);
//   }

  if (c->handshake_completed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      nullptr, // recv_version_negotiation
//int ngtcp2_crypto_encrypt_cb
[](uint8_t *dest, const ngtcp2_crypto_aead *aead,
                             const uint8_t *plaintext, size_t plaintextlen,
                             const uint8_t *key, const uint8_t *nonce,
                             size_t noncelen, const uint8_t *ad, size_t adlen) {
  if (ngtcp2_crypto_encrypt(dest, aead, plaintext, plaintextlen, key, nonce,
                            noncelen, ad, adlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
},   
//int ngtcp2_crypto_encrypt_cb
[](uint8_t *dest, const ngtcp2_crypto_aead *aead,
                             const uint8_t *plaintext, size_t plaintextlen,
                             const uint8_t *key, const uint8_t *nonce,
                             size_t noncelen, const uint8_t *ad, size_t adlen) {
  if (ngtcp2_crypto_encrypt(dest, aead, plaintext, plaintextlen, key, nonce,
                            noncelen, ad, adlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
      //int do_hp_mask
      [](uint8_t *dest, const ngtcp2_crypto_cipher *hp,
               const uint8_t *hp_key, const uint8_t *sample) {
  if (ngtcp2_crypto_hp_mask(dest, hp, hp_key, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

//   if (!config.quiet && config.show_secret) {
//     debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);
//   }

  return 0;
},
      //int recv_stream_data
      [](ngtcp2_conn *conn, int64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
//   if (!config.quiet && !config.no_quic_dump) {
//     debug::print_stream_data(stream_id, data, datalen);
//   }

  auto c = static_cast<T *>(user_data);

  if (c->recv_stream_data(stream_id, fin, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      //int acked_crypto_offset
      [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                        uint64_t offset, size_t datalen, void *user_data) {
  auto c = static_cast<T *>(user_data);
  c->remove_tx_crypto_data(crypto_level, offset, datalen);

  return 0;
},
      //int acked_stream_data_offset
      [](ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto c = static_cast<T *>(user_data);
  if (c->acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
      nullptr, // stream_open
      //int stream_close
      [](ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto c = static_cast<T *>(user_data);

  if (c->on_stream_close(stream_id, app_error_code) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      nullptr, // recv_stateless_reset
      //int recv_retry
      [](ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_pkt_retry *retry, void *user_data) {
  // Re-generate handshake secrets here because connection ID might
  // change.
  auto c = static_cast<T *>(user_data);

  c->on_recv_retry();

  return 0;
},
      //int extend_max_streams_bidi
      [](ngtcp2_conn *conn, uint64_t max_streams,
                            void *user_data) {
  auto c = static_cast<T *>(user_data);

  if (c->on_extend_max_streams() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      nullptr, // extend_max_streams_uni
      //int rand
      [](ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx,
         void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
},
      //int get_new_connection_id
      [](ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto c = static_cast<T *>(user_data);
  return c->get_new_connection_id(conn,cid,token,cidlen);
},
      //int remove_connection_id
      [](ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  return 0;
},
      //int update_key
      [](ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
  auto c = static_cast<T *>(user_data);

  if (c->update_key(rx_secret, tx_secret, rx_key, rx_iv, tx_key, tx_iv,
                    current_rx_secret, current_tx_secret, secretlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      //int path_validation
      [](ngtcp2_conn *conn, const ngtcp2_path *path,
                    ngtcp2_path_validation_result res, void *user_data) {
//   if (!config.quiet) {
//     debug::path_validation(path, res);
//   }
  return 0;
},
      //int select_preferred_address
      [](ngtcp2_conn *conn, ngtcp2_addr *dest,
                             const ngtcp2_preferred_addr *paddr,
                             void *user_data) {
  auto c = static_cast<T *>(user_data);
  Address addr;

//   if (config.no_preferred_addr) {
//     return 0;
//   }

  if (c->select_preferred_address(addr, paddr) != 0) {
    dest->addrlen = 0;
    return 0;
  }

  dest->addrlen = addr.len;
  memcpy(dest->addr, &addr.su, dest->addrlen);

  return 0;
},
      //int stream_reset
      [](ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto c = static_cast<T *>(user_data);

  if (c->on_stream_reset(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
},
      nullptr, // extend_max_remote_streams_bidi,
      nullptr, // extend_max_remote_streams_uni,
      //int extend_max_stream_data
      [](ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data) {
  auto c = static_cast<T *>(user_data);
  if (c->extend_max_stream_data(stream_id, max_data) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
  };

  auto dis = std::uniform_int_distribution<uint8_t>(
      0, std::numeric_limits<uint8_t>::max());
  auto generate_cid = [&dis](ngtcp2_cid &cid, size_t len) {
    cid.datalen = len;
    std::generate(std::begin(cid.data), std::begin(cid.data) + cid.datalen,
                  [&dis]() { return dis(randgen); });
  };

  ngtcp2_cid scid, dcid;
  generate_cid(scid, 17);
  //if (config.dcid.datalen == 0) {
    generate_cid(dcid, 18);
  //} else {
  //  dcid = config.dcid;
  //}

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = IsDebug() ? printf : nullptr;
//   if (config.qlog_file) {
//     qlog_ = fopen(config.qlog_file, "w");
//     if (qlog_ == nullptr) {
//       std::cerr << "Could not open qlog file " << config.qlog_file << ": "
//                 << strerror(errno) << std::endl;
//       return -1;
//     }
//     settings.qlog.write = ::write_qlog;
//     settings.qlog.odcid = dcid;
//   }
//  settings.initial_ts = util::timestamp(loop_);
  auto &params = settings.transport_params;
  params.initial_max_stream_data_bidi_local = this->manager_->max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      this->manager_->max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = this->manager_->max_stream_data_uni;
  params.initial_max_data = this->manager_->max_data;
  params.initial_max_streams_bidi = this->manager_->max_streams_bidi;
  params.initial_max_streams_uni = this->manager_->max_streams_uni;
  params.max_idle_timeout = this->manager_->timeout;
  params.active_connection_id_limit = 7;

  auto path = ngtcp2_path{
      {local_addr.len, const_cast<uint8_t *>(
                           reinterpret_cast<const uint8_t *>(&local_addr.su))},
      {remote_addr.len, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
                            &remote_addr.su))}};
  auto rv = ngtcp2_conn_client_new(&this->conn_, &dcid, &scid, &path, version,
                                       &callbacks, &settings, nullptr, this);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_client_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  if (init_ssl() != 0) {
    return -1;
  }

  if (setup_initial_crypto_context() != 0) {
    return -1;
  }

  if (early_data_ && this->manager_->tp_file) {
    ngtcp2_transport_params params;
    if (read_transport_params(this->manager_->tp_file, &params) != 0) {
      std::cerr << "Could not read transport parameters from " << this->manager_->tp_file
                << std::endl;
      early_data_ = false;
    } else {
      ngtcp2_conn_set_early_remote_transport_params(this->conn_, &params);
      make_stream_early();
    }
  }

//   ev_io_set(&wev_, fd_, EV_WRITE);
//   ev_io_set(&rev_, fd_, EV_READ);

//   ev_io_start(loop_, &rev_);
//   ev_timer_again(loop_, &timer_);

//   ev_signal_start(loop_, &sigintev_);

  return 0;
}

int init_ssl() {
  if (ssl_) {
    SSL_free(ssl_);
  }

  ssl_ = SSL_new(this->ssl_ctx_);
  SSL_set_app_data(ssl_, this);
  SSL_set_connect_state(ssl_);

  const uint8_t *alpn = nullptr;
  size_t alpnlen;

  switch (version_) {
  case NGTCP2_PROTO_VER:
    alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_H3);
    alpnlen = str_size(NGTCP2_ALPN_H3);
    break;
  }
  if (alpn) {
    SSL_set_alpn_protos(ssl_, alpn, alpnlen);
  }

  if (numeric_host(addr_)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    SSL_set_tlsext_host_name(ssl_, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl_, addr_);
  }

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(this->conn_, &params);

  std::array<uint8_t, 64> buf;

  auto nwrite = ngtcp2_encode_transport_params(
      buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
              << std::endl;
    return -1;
  }

  if (SSL_set_quic_transport_params(ssl_, buf.data(), nwrite) != 1) {
    std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
    return -1;
  }

  if (this->manager_->session_file) {
    auto f = BIO_new_file(this->manager_->session_file, "r");
    if (f == nullptr) {
      std::cerr << "Could not read TLS session file " << this->manager_->session_file
                << std::endl;
    } else {
      auto session = PEM_read_bio_SSL_SESSION(f, nullptr, 0, nullptr);
      BIO_free(f);
      if (session == nullptr) {
        std::cerr << "Could not read TLS session file " << this->manager_->session_file
                  << std::endl;
      } else {
        if (!SSL_set_session(ssl_, session)) {
          std::cerr << "Could not set session" << std::endl;
        } else if (!this->manager_->disable_early_data &&
                   SSL_SESSION_get_max_early_data(session)) {
          early_data_ = true;
          SSL_set_quic_early_data_enabled(ssl_, 1);
        }
        SSL_SESSION_free(session);
      }
    }
  }

  return 0;
}

int setup_initial_crypto_context() {
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN> initial_secret,
      rx_secret, tx_secret;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN> rx_key, rx_hp_key, tx_key,
      tx_hp_key;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN> rx_iv, tx_iv;

  auto dcid = ngtcp2_conn_get_dcid(this->conn_);

  if (ngtcp2_crypto_derive_and_install_initial_key(
          this->conn_, rx_secret.data(), tx_secret.data(), initial_secret.data(),
          rx_key.data(), rx_iv.data(), rx_hp_key.data(), tx_key.data(),
          tx_iv.data(), tx_hp_key.data(), dcid,
          NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_initial_key() failed"
              << std::endl;
    return -1;
  }

//   if (!config.quiet && config.show_secret) {
//     debug::print_initial_secret(initial_secret.data(), initial_secret.size());

//     std::cerr << "initial rx secret" << std::endl;
//     debug::print_secrets(rx_secret.data(), rx_secret.size(), rx_key.data(),
//                          rx_key.size(), rx_iv.data(), rx_iv.size(),
//                          rx_hp_key.data(), rx_hp_key.size());
//     std::cerr << "initial tx secret" << std::endl;
//     debug::print_secrets(tx_secret.data(), tx_secret.size(), tx_key.data(),
//                          tx_key.size(), tx_iv.data(), tx_iv.size(),
//                          tx_hp_key.data(), tx_hp_key.size());
//   }

  return 0;
}

void make_stream_early() {
//   if (nstreams_done_ >= config.nstreams) {
//     return;
//   }

  int64_t stream_id;
  auto rv = ngtcp2_conn_open_bidi_stream(this->conn_, &stream_id, nullptr);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_bidi_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return;
  }

//   // TODO Handle error
//   if (setup_httpconn() != 0) {
//     return;
//   }

//   auto stream = std::make_unique<Stream>(
//       config.requests[nstreams_done_ % config.requests.size()], stream_id);

//   if (submit_http_request(stream.get()) != 0) {
//     return;
//   }

//   if (!config.download.empty()) {
//     stream->open_file(stream->req.path);
//   }
//   streams_.emplace(stream_id, std::move(stream));

//   ++nstreams_done_;
}

int select_preferred_address(Address &selected_addr,
                                     const ngtcp2_preferred_addr *paddr) {
//   int af;
//   const uint8_t *binaddr;
//   uint16_t port;
//   constexpr uint8_t empty_addr[] = {0, 0, 0, 0, 0, 0, 0, 0,
//                                     0, 0, 0, 0, 0, 0, 0, 0};
//   if (local_addr_.su.sa.sa_family == AF_INET &&
//       memcmp(empty_addr, paddr->ipv4_addr, sizeof(paddr->ipv4_addr)) != 0) {
//     af = AF_INET;
//     binaddr = paddr->ipv4_addr;
//     port = paddr->ipv4_port;
//   } else if (local_addr_.su.sa.sa_family == AF_INET6 &&
//              memcmp(empty_addr, paddr->ipv6_addr, sizeof(paddr->ipv6_addr)) !=
//                  0) {
//     af = AF_INET6;
//     binaddr = paddr->ipv6_addr;
//     port = paddr->ipv6_port;
//   } else {
//     return -1;
//   }

//   char host[NI_MAXHOST];
//   if (inet_ntop(af, binaddr, host, sizeof(host)) == nullptr) {
//     std::cerr << "inet_ntop: " << strerror(errno) << std::endl;
//     return -1;
//   }

//   if (!config.quiet) {
//     std::cerr << "selected server preferred_address is [" << host
//               << "]:" << port << std::endl;
//   }

//   addrinfo hints{};
//   addrinfo *res;

//   hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
//   hints.ai_family = af;
//   hints.ai_socktype = SOCK_DGRAM;

//   if (auto rv = getaddrinfo(host, std::to_string(port).c_str(), &hints, &res);
//       rv != 0) {
//     std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
//     return -1;
//   }

//   assert(res);

//   selected_addr.len = res->ai_addrlen;
//   memcpy(&selected_addr.su, res->ai_addr, res->ai_addrlen);

//   freeaddrinfo(res);

  return 0;
}
 };

 template<class T, class TManager, class TSocket, class TBase>
 class QuicServerHandlerT : public QuicHandlerBaseT<T,TManager,TSocket,TBase>
 {
   typedef QuicServerHandlerT<T,TManager,TSocket,TBase> This;
   typedef QuicHandlerBaseT<T,TManager,TSocket,TBase> Base;
 protected:
  ngtcp2_cid scid_;
  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  // draining_ becomes true when draining period starts.
  bool draining_;

public:
	QuicServerHandlerT(TManager* manager, TSocket *ep, SSL_CTX *ssl_ctx, const ngtcp2_cid *rcid):Base(manager,ep,ssl_ctx)
	, scid_{}
    , pscid_{}
    , rcid_(*rcid)
	, draining_(false)
	{
	}

const ngtcp2_cid *scid() const { return &scid_; }

const ngtcp2_cid *pscid() const { return &pscid_; }

const ngtcp2_cid *rcid() const { return &rcid_; }

bool draining() const { return draining_; }

int init(const sockaddr *sa, socklen_t salen,
                  const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                  const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
                  uint32_t version) 
{
  this->remote_addr_.len = salen;
  memcpy(&this->remote_addr_.su.sa, sa, salen);	  

  this->ssl_ = SSL_new(this->ssl_ctx_);
  SSL_set_app_data(this->ssl_, this);
  SSL_set_accept_state(this->ssl_);
  SSL_set_quic_early_data_enabled(this->ssl_, 1);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr, // client_initial
      //::recv_client_initial,
      [](ngtcp2_conn *conn, const ngtcp2_cid *dcid,void *user_data) -> int {
        auto h = static_cast<This *>(user_data);

        if (h->recv_client_initial(dcid) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        return 0;
      },
      //::recv_crypto_data,
      [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) -> int {
        // if (!config.quiet && !config.no_quic_dump) {
        //   debug::print_crypto_data(crypto_level, data, datalen);
        // }

        auto h = static_cast<This *>(user_data);

        if (h->recv_crypto_data(crypto_level, data, datalen) != 0) {
          auto err = ngtcp2_conn_get_tls_error(conn);
          if (err) {
            return err;
          }
          return NGTCP2_ERR_CRYPTO;
        }

        return 0;
      },
      //::handshake_completed,
      [](ngtcp2_conn *conn, void *user_data) {
        auto h = static_cast<This *>(user_data);

        // if (!config.quiet) {
        //   debug::handshake_completed(conn, user_data);
        // }

        if (h->handshake_completed() != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        return 0;
      },
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,      
      //do_hp_mask,
      [](uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                    const uint8_t *hp_key, const uint8_t *sample) {
        if (ngtcp2_crypto_hp_mask(dest, hp, hp_key, sample) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        // if (!config.quiet && config.show_secret) {
        //   debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);
        // }

        return 0;
      },      
      //::recv_stream_data,
      [](ngtcp2_conn *conn, int64_t stream_id, int fin,
                          uint64_t offset, const uint8_t *data, size_t datalen,
                          void *user_data, void *stream_user_data) {
        auto h = static_cast<This *>(user_data);

        if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        return 0;
      },
      //acked_crypto_offset,  
      [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                              uint64_t offset, size_t datalen, void *user_data) {
        auto h = static_cast<This *>(user_data);
        h->remove_tx_crypto_data(crypto_level, offset, datalen);
        return 0;
      },    
      //::acked_stream_data_offset,
      [](ngtcp2_conn *conn, int64_t stream_id,
                                  uint64_t offset, size_t datalen, void *user_data,
                                  void *stream_user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->acked_stream_data_offset(stream_id, datalen) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },      
      //stream_open,
      [](ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
        auto h = static_cast<This *>(user_data);
        h->on_stream_open(stream_id);
        return 0;
      },
      //stream_close,
      [](ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                      void *user_data, void *stream_user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->on_stream_close(stream_id, app_error_code) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },
      nullptr, // recv_stateless_reset
      nullptr, // recv_retry
      nullptr, // extend_max_streams_bidi
      nullptr, // extend_max_streams_uni
      //rand,
      [](ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx,
              void *user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->rand(conn, dest, destlen, ctx) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },
      //get_new_connection_id,
      [](ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                size_t cidlen, void *user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->get_new_connection_id(conn, cid, token, cidlen) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },      
      //remove_connection_id,
      [](ngtcp2_conn *conn, const ngtcp2_cid *cid,
                              void *user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->remove_connection_id(conn, cid) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },      
      //::update_key,tx是发送(transport),rx是接收(receive)
      [](ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                    uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
                    const uint8_t *current_rx_secret,
                    const uint8_t *current_tx_secret, size_t secretlen,
                    void *user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->update_key(rx_secret, tx_secret, rx_key, rx_iv, tx_key, tx_iv,
                          current_rx_secret, current_tx_secret, secretlen) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },      
      //path_validation,
      [](ngtcp2_conn *conn, const ngtcp2_path *path,
                          ngtcp2_path_validation_result res, void *user_data) {
        // if (!config.quiet) {
        //   debug::path_validation(path, res);
        // }
        return 0;
      },
      nullptr, // select_preferred_addr      
      //::stream_reset,
      [](ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->on_stream_reset(stream_id) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },      
      //::extend_max_remote_streams_bidi,
      [](ngtcp2_conn *conn, uint64_t max_streams,
                                        void *user_data) {
        auto h = static_cast<This *>(user_data);
        h->extend_max_remote_streams_bidi(max_streams);
        return 0;
      },
      nullptr, // extend_max_remote_streams_uni,      
      //::extend_max_stream_data,
      [](ngtcp2_conn *conn, int64_t stream_id,
                              uint64_t max_data, void *user_data,
                              void *stream_user_data) {
        auto h = static_cast<This *>(user_data);
        if (h->extend_max_stream_data(stream_id, max_data) != 0) {
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
      },
  };

  auto dis = std::uniform_int_distribution<>(0);

  scid_.datalen = NGTCP2_SV_SCIDLEN;
  std::generate(scid_.data, scid_.data + scid_.datalen,
                [&dis]() { return dis(randgen)%255; });
/*
  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = IsDebug() ? printf : nullptr;
  settings.initial_ts = util::timestamp(loop_);
  settings.token = ngtcp2_vec{const_cast<uint8_t *>(token), tokenlen};
  if (!config.qlog_dir.empty()) {
    auto path = std::string{config.qlog_dir};
    path += '/';
    path += util::format_hex(scid_.data, scid_.datalen);
    path += ".qlog";
    qlog_ = fopen(path.c_str(), "w");
    if (qlog_ == nullptr) {
      std::cerr << "Could not open qlog file " << path << ": "
                << strerror(errno) << std::endl;
      return -1;
    }
    settings.qlog.write = ::write_qlog;
    settings.qlog.odcid = *scid;
  }
  auto &params = settings.transport_params;
  params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      config.max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = config.max_stream_data_uni;
  params.initial_max_data = config.max_data;
  params.initial_max_streams_bidi = config.max_streams_bidi;
  params.initial_max_streams_uni = config.max_streams_uni;
  params.max_idle_timeout = config.timeout;
  params.stateless_reset_token_present = 1;
  params.active_connection_id_limit = 7;

  if (ocid) {
    params.original_connection_id = *ocid;
    params.original_connection_id_present = 1;
  }

  std::generate(std::begin(params.stateless_reset_token),
                std::end(params.stateless_reset_token),
                [&dis]() { return dis(randgen); });

  if (config.preferred_ipv4_addr.len || config.preferred_ipv6_addr.len) {
    params.preferred_address_present = 1;
    if (config.preferred_ipv4_addr.len) {
      auto &dest = params.preferred_address.ipv4_addr;
      const auto &addr = config.preferred_ipv4_addr;
      assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
      memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
      params.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
    }
    if (config.preferred_ipv6_addr.len) {
      auto &dest = params.preferred_address.ipv6_addr;
      const auto &addr = config.preferred_ipv6_addr;
      assert(sizeof(dest) == sizeof(addr.su.in6.sin6_addr));
      memcpy(&dest, &addr.su.in6.sin6_addr, sizeof(dest));
      params.preferred_address.ipv6_port = htons(addr.su.in6.sin6_port);
    }

    auto &token = params.preferred_address.stateless_reset_token;
    std::generate(std::begin(token), std::end(token),
                  [&dis]() { return dis(randgen); });

    pscid_.datalen = NGTCP2_SV_SCIDLEN;
    std::generate(pscid_.data, pscid_.data + pscid_.datalen,
                  [&dis]() { return dis(randgen); });
    params.preferred_address.cid = pscid_;
  }

  auto path = ngtcp2_path{
      {ep.addr.len,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&ep.addr.su)),
       const_cast<Endpoint *>(&ep)},
      {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
  if (auto rv = ngtcp2_conn_server_new(&conn_, dcid, &scid_, &path, version,
                                       &callbacks, &settings, nullptr, this);
      rv != 0) {
    std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  std::array<uint8_t, 512> buf;

  auto nwrite = ngtcp2_encode_transport_params(
      buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      &params);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
              << std::endl;
    return -1;
  }

  if (SSL_set_quic_transport_params(ssl_, buf.data(), nwrite) != 1) {
    std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
    return -1;
  }

  ev_io_set(&wev_, endpoint_->fd, EV_WRITE);
  ev_timer_again(loop_, &timer_);*/

  return 0;
}

int recv_client_initial(const ngtcp2_cid *dcid) {
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN> initial_secret,
      rx_secret, tx_secret;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN> rx_key, rx_hp_key, tx_key,
      tx_hp_key;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN> rx_iv, tx_iv;

  if (ngtcp2_crypto_derive_and_install_initial_key(
          this->conn_, rx_secret.data(), tx_secret.data(), initial_secret.data(),
          rx_key.data(), rx_iv.data(), rx_hp_key.data(), tx_key.data(),
          tx_iv.data(), tx_hp_key.data(), dcid,
          NGTCP2_CRYPTO_SIDE_SERVER) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_initial_key() failed"
              << std::endl;
    return -1;
  }

  /*if (IsDebug() && config.show_secret) {
    debug::print_initial_secret(initial_secret.data(), initial_secret.size());

    std::cerr << "initial rx secret" << std::endl;
    debug::print_secrets(rx_secret.data(), rx_secret.size(), rx_key.data(),
                         rx_key.size(), rx_iv.data(), rx_iv.size(),
                         rx_hp_key.data(), rx_hp_key.size());
    std::cerr << "initial tx secret" << std::endl;
    debug::print_secrets(tx_secret.data(), tx_secret.size(), tx_key.data(),
                         tx_key.size(), tx_iv.data(), tx_iv.size(),
                         tx_hp_key.data(), tx_hp_key.size());
  }*/

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
 *	@brief QuicClientManagerT 定义.
 *
 *	封装QuicClientManagerT，实现Quick服务
 */
template<class T, class TSocket, class THandler>
class QuicClientManagerT : public QuicManagerBaseT<T,THandler>
{
	typedef QuicClientManagerT<T,TSocket,THandler> This;
	typedef QuicManagerBaseT<T,THandler> Base;
public:
	typedef THandler Handler;
protected:
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  const char *tp_file;
  // disable_early_data disables early data.
  bool disable_early_data;
public:
    inline bool IsServer() { return false; }
};

/*!
 *	@brief QuicServerManagerT 定义.
 *
 *	封装QuicServerManagerT，实现Quick服务
 */
template<class T, class TSocket, class THandler>
class QuicServerManagerT : public QuicManagerBaseT<T,THandler>
{
	typedef QuicServerManagerT<T,TSocket,THandler> This;
	typedef QuicManagerBaseT<T,THandler> Base;
public:
	typedef THandler Handler;
protected:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;

public:
	QuicServerManagerT(const char *private_key_file, const char *cert_file):Base(private_key_file, cert_file)
	{

	}

	~QuicServerManagerT() 
	{

	}

  Address preferred_ipv4_addr;
  Address preferred_ipv6_addr;
  // htdocs is a root directory to serve documents.
  std::string docs;
  // mime_types_file is a path to "MIME media types and the
  // extensions" file.  Ubuntu mime-support package includes it in
  // /etc/mime/types.
  const char *mime_types_file;
  // mime_types maps file extension to MIME media type.
  std::map<std::string, std::string> mime_types;
  // server name
  std::string server;
  // port is the port number which server listens on for incoming
  // connections.
  uint16_t port;
  // validate_addr is true if server requires address validation.
  bool validate_addr;
  // early_response is true if server starts sending response when it
  // receives HTTP header fields without waiting for request body.  If
  // HTTP response data is written before receiving request body,
  // STOP_SENDING is sent.
  bool early_response;
  // verify_client is true if server verifies client with X.509
  // certificate based authentication.
  bool verify_client;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump;
  // max_dyn_length is the maximum length of dynamically generated
  // response.
  uint64_t max_dyn_length;

static uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen,
									uint32_t version) {
	uint32_t h = 0x811C9DC5u;
	const uint8_t *p = (const uint8_t *)sa;
	const uint8_t *ep = p + salen;
	for (; p != ep; ++p) {
		h ^= *p;
		h *= 0x01000193u;
	}
	version = htonl(version);
	p = (const uint8_t *)&version;
	ep = p + sizeof(version);
	for (; p != ep; ++p) {
		h ^= *p;
		h *= 0x01000193u;
	}
	h &= 0xf0f0f0f0u;
	h |= 0x0a0a0a0au;
	return h;
}

static inline std::string make_cid_key(const ngtcp2_cid *cid) {
  return std::string(cid->data, cid->data + cid->datalen);
}

static inline std::string make_cid_key(const uint8_t *cid, size_t cidlen) {
  return std::string(cid, cid + cidlen);
}

static inline void generate_rand_data(uint8_t *buf, size_t len) {
  auto dis = std::uniform_int_distribution<>(0);
  std::generate_n(buf, len, [&dis]() { return dis(randgen)%255; });
}

static bool packet_lost(double prob) {
		auto p = std::uniform_real_distribution<>(0, 1)(randgen);
		return p < prob;
	}

inline int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                             size_t &ivlen, const uint8_t *rand_data,
                             size_t rand_datalen) {
  std::array<uint8_t, 32> secret;

  if (ngtcp2_crypto_hkdf_extract(
          secret.data(), &token_md_, this->static_secret.data(),
          this->static_secret.size(), rand_data, rand_datalen) != 0) {
    return -1;
  }

  keylen = ngtcp2_crypto_aead_keylen(&token_aead_);
  ivlen = ngtcp2_crypto_packet_protection_ivlen(&token_aead_);

  if (ngtcp2_crypto_derive_packet_protection_key(key, iv, nullptr, &token_aead_,
                                                 &token_md_, secret.data(),
                                                 secret.size()) != 0) {
    return -1;
  }

  return 0;
}

inline int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                           socklen_t salen, const ngtcp2_cid *ocid) {
  std::array<uint8_t, 4096> plaintext;

  uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  auto p = std::begin(plaintext);
  p = std::copy_n(reinterpret_cast<const uint8_t *>(sa), salen, p);
  // Host byte order
  p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);
  p = std::copy_n(ocid->data, ocid->datalen, p);

  std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  generate_rand_data(rand_data.data(), rand_data.size());
  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data.data(),
                       rand_data.size()) != 0) {
    return -1;
  }

  auto plaintextlen = std::distance(std::begin(plaintext), p);
  if (ngtcp2_crypto_encrypt(token, &token_aead_, plaintext.data(), plaintextlen,
                            key.data(), iv.data(), ivlen,
                            reinterpret_cast<const uint8_t *>(sa),
                            salen) != 0) {
    return -1;
  }

  tokenlen = plaintextlen + ngtcp2_crypto_aead_taglen(&token_aead_);
  memcpy(token + tokenlen, rand_data.data(), rand_data.size());
  tokenlen += rand_data.size();

  return 0;
}

int verify_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                         const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                            port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (
      rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (IsDebug()) {
    std::cerr << "Verifying token from [" << host.data() << "]:" << port.data()
              << std::endl;
  }

  if (IsDebug()) {
    std::cerr << "Received address validation token:" << std::endl;
    //util::hexdump(stderr, hd->token, hd->tokenlen);
  }

  if (hd->tokenlen < TOKEN_RAND_DATALEN) {
    if (IsDebug()) {
      std::cerr << "Token is too short" << std::endl;
    }
    return -1;
  }

  auto rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
  auto ciphertext = hd->token;
  auto ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

  std::array<uint8_t, 32> key, iv;
  auto keylen = key.size();
  auto ivlen = iv.size();

  if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data,
                       TOKEN_RAND_DATALEN) != 0) {
    return -1;
  }

  std::array<uint8_t, 4096> plaintext;

  if (ngtcp2_crypto_decrypt(plaintext.data(), &token_aead_, ciphertext,
                            ciphertextlen, key.data(), iv.data(), ivlen,
                            reinterpret_cast<const uint8_t *>(sa),
                            salen) != 0) {
    if (IsDebug()) {
      std::cerr << "Could not decrypt token" << std::endl;
    }
    return -1;
  }

  assert(ciphertextlen >= ngtcp2_crypto_aead_taglen(&token_aead_));

  auto plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&token_aead_);
  if (plaintextlen < salen + sizeof(uint64_t)) {
    if (IsDebug()) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  auto cil = plaintextlen - salen - sizeof(uint64_t);
  if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
    if (IsDebug()) {
      std::cerr << "Bad token construction" << std::endl;
    }
    return -1;
  }

  if (memcmp(plaintext.data(), sa, salen) != 0) {
    if (IsDebug()) {
      std::cerr << "Client address does not match" << std::endl;
    }
    return -1;
  }

  uint64_t t;
  memcpy(&t, plaintext.data() + salen, sizeof(uint64_t));

  uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();

  // Allow 10 seconds window
  if (t + 10ULL * NGTCP2_SECONDS < now) {
    if (IsDebug()) {
      std::cerr << "Token has been expired" << std::endl;
    }
    return -1;
  }

  ngtcp2_cid_init(ocid, plaintext.data() + salen + sizeof(uint64_t), cil);

  return 0;
}

int send_version_negotiation(TSocket* ep, uint32_t version, const uint8_t *dcid,size_t dcidlen, const uint8_t *scid,size_t scidlen, const sockaddr *sa, socklen_t salen) {
	uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
	uint32_t sv[2] = {0};

	sv[0] = generate_reserved_version(sa, salen, version);
	sv[1] = NGTCP2_PROTO_VER;

	auto nwrite = ngtcp2_pkt_write_version_negotiation(
		buf, sizeof(buf),
		std::uniform_int_distribution<>(0)(randgen)%255,
		dcid, dcidlen, scid, scidlen, sv, 2);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_version_negotiation: "
				<< ngtcp2_strerror(nwrite) << std::endl;
		return -1;
	}

	ep->SendBuf((const char*)buf, nwrite, sa, salen);

	return 0;
	}

int send_retry(TSocket* ep, const ngtcp2_pkt_hd *chd, const sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;
  
  auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
                            port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
    return -1;
  }

  if (IsDebug()) {
    std::cerr << "Sending Retry packet to [" << host.data()
              << "]:" << port.data() << std::endl;
  }

  std::array<uint8_t, 256> token;
  size_t tokenlen = token.size();

  if (generate_token(token.data(), tokenlen, sa, salen, &chd->dcid) != 0) {
    return -1;
  }

  if (IsDebug()) {
    std::cerr << "Generated address validation token:" << std::endl;
    //util::hexdump(stderr, token.data(), tokenlen);
  }

  uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
  ngtcp2_cid scid;

  scid.datalen = NGTCP2_SV_SCIDLEN;
  auto dis = std::uniform_int_distribution<>(0);
  std::generate(scid.data, scid.data + scid.datalen,
                [&dis]() { return dis(randgen)%255; });

  auto nwrite =
      ngtcp2_crypto_write_retry(buf, sizeof(buf), &chd->scid, &scid,
                                &chd->dcid, token.data(), tokenlen);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_crypto_write_retry failed" << std::endl;
    return -1;
  }

  ep->SendBuf((const char*)buf, nwrite, sa, salen);

  return 0;
}

int send_stateless_connection_close(TSocket* ep, const ngtcp2_pkt_hd *chd, const sockaddr *sa, socklen_t salen) {
  uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};

  auto nwrite = ngtcp2_crypto_write_connection_close(
      buf, sizeof(buf), &chd->scid, &chd->dcid, NGTCP2_INVALID_TOKEN);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_crypto_write_connection_close failed" << std::endl;
    return -1;
  }

  ep->SendBuf((const char*)buf, nwrite, sa, salen);

  return 0;
}

inline void associate_cid(const ngtcp2_cid *cid, Handler *h) {
  ctos_.emplace(make_cid_key(cid), make_cid_key(h->scid()));
}

inline void dissociate_cid(const ngtcp2_cid *cid) {
  ctos_.erase(make_cid_key(cid));
}

void remove(const Handler *h) {
  ctos_.erase(make_cid_key(h->rcid()));
  ctos_.erase(make_cid_key(h->pscid()));

  auto conn = h->conn();
  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(conn));
  ngtcp2_conn_get_scid(conn, cids.data());

  for (auto &cid : cids) {
    ctos_.erase(make_cid_key(&cid));
  }

  handlers_.erase(make_cid_key(h->scid()));
}

protected:
	//
	//解析数据包
	virtual int OnRecvBuf(TSocket* ep, const char* buf, int & nread, const SOCKADDR* sa, int salen) { 
      T* pT = static_cast<T*>(this);
// 		sockaddr_union su;
//   socklen_t addrlen;
//   std::array<uint8_t, 64_k> buf;
  ngtcp2_pkt_hd hd;
//   size_t pktcnt = 0;

//   for (; pktcnt < 10;) {
//     addrlen = sizeof(su);
//     auto nread =
//         recvfrom(ep.fd, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);
//     if (nread == -1) {
//       if (!(errno == EAGAIN || errno == ENOTCONN)) {
//         std::cerr << "recvfrom: " << strerror(errno) << std::endl;
//       }
//       return 0;
//     }

//     ++pktcnt;

//     if (!config.quiet) {
//       std::cerr << "Received packet: local="
//                 << util::straddr(&ep.addr.su.sa, ep.addr.len)
//                 << " remote=" << util::straddr(&su.sa, addrlen) << " " << nread
//                 << " bytes" << std::endl;
//     }

    if (packet_lost(this->rx_loss_prob)) {
      if (IsDebug()) {
        std::cerr << "** Simulated incoming packet loss **" << std::endl;
      }
      return 0;
    }

    if (nread == 0) {
      return 0;
    }

    uint32_t version;
    const uint8_t *dcid, *scid;
    size_t dcidlen, scidlen;
    auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen,
                                                &scid, &scidlen, (const uint8_t *)buf,
                                                nread, NGTCP2_SV_SCIDLEN);
    if (rv != 0) {
      if (rv == 1) {
        send_version_negotiation(ep, version, scid, scidlen, dcid, dcidlen, sa);
      	return SOCKET_PACKET_FLAG_COMPLETE;
      }
      std::cerr << "Could not decode version and CID from QUIC packet header: "
                << ngtcp2_strerror(rv) << std::endl;
      return SOCKET_PACKET_FLAG_COMPLETE;
    }

    auto dcid_key = make_cid_key(dcid, dcidlen);

    auto handler_it = handlers_.find(dcid_key);
    if (handler_it == std::end(handlers_)) {
      auto ctos_it = ctos_.find(dcid_key);
      if (ctos_it == std::end(ctos_)) {
        rv = ngtcp2_accept(&hd, (const uint8_t *)buf, nread);
        if (rv == -1) {
          if (IsDebug()) {
            std::cerr << "Unexpected packet received: length=" << nread
                      << std::endl;
          }
          return SOCKET_PACKET_FLAG_COMPLETE;
        } else if (rv == 1) {
          if (IsDebug()) {
            std::cerr << "Unsupported version: Send Version Negotiation"
                      << std::endl;
          }
          send_version_negotiation(ep, hd.version, hd.scid.data, hd.scid.datalen,
                                   hd.dcid.data, hd.dcid.datalen, sa);
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        ngtcp2_cid ocid;
        ngtcp2_cid *pocid = nullptr;
        switch (hd.type) {
        case NGTCP2_PKT_INITIAL:
          if (validate_addr || hd.tokenlen) {
            std::cerr << "Perform stateless address validation" << std::endl;
            if (hd.tokenlen == 0) {
              send_retry(ep, &hd, sa);
              return SOCKET_PACKET_FLAG_COMPLETE;
            }
            if (verify_token(&ocid, &hd, sa, salen) != 0) {
              send_stateless_connection_close(ep, &hd, sa);
              return SOCKET_PACKET_FLAG_COMPLETE;
            }
            pocid = &ocid;
          }
          break;
        case NGTCP2_PKT_0RTT:
          send_retry(ep, &hd, sa);
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        auto h = std::unique_ptr<Handler>(new Handler(pT, ep, Base::ssl_ctx_, &hd.dcid));
        if (h->init(sa, &hd.scid, &hd.dcid, pocid, hd.token,
                    hd.tokenlen, hd.version) != 0) {
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        switch (h->on_read(ep, sa, (uint8_t *)buf, nread)) {
        case 0:
          break;
        case NETWORK_ERR_RETRY:
          send_retry(ep, &hd, sa);
          return SOCKET_PACKET_FLAG_COMPLETE;
        default:
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        switch (h->on_write()) {
        case 0:
          break;
        default:
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        auto scid = h->scid();
        auto scid_key = make_cid_key(scid);
        ctos_.emplace(dcid_key, scid_key);

        auto pscid = h->pscid();
        if (pscid->datalen) {
          auto pscid_key = make_cid_key(pscid);
          ctos_.emplace(pscid_key, scid_key);
        }

        handlers_.emplace(scid_key, std::move(h));
        return SOCKET_PACKET_FLAG_COMPLETE;
      }
      if (IsDebug()) {
        std::cerr << "Forward CID=" << format_hex((*ctos_it).first)
                  << " to CID=" << format_hex((*ctos_it).second)
                  << std::endl;
      }
      handler_it = handlers_.find((*ctos_it).second);
      assert(handler_it != std::end(handlers_));
    }

    auto h = (*handler_it).second.get();
    if (ngtcp2_conn_is_in_closing_period(h->conn())) {
      // TODO do exponential backoff.
      switch (h->send_conn_close()) {
      case 0:
        break;
      default:
        remove(h);
      }
      return SOCKET_PACKET_FLAG_COMPLETE;
    }
    if (h->draining()) {
      return SOCKET_PACKET_FLAG_COMPLETE;
    }

    rv = h->on_read(ep, sa, (uint8_t *)buf, nread);
    if (rv != 0) {
      if (rv != NETWORK_ERR_CLOSE_WAIT) {
        remove(h);
      }
      return SOCKET_PACKET_FLAG_COMPLETE;
    }

    h->signal_write();
//   }

  return SOCKET_PACKET_FLAG_COMPLETE;
	}
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

#endif//_H_XHTTP_IMPL_H_
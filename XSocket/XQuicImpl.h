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

#include <sys/time.h>

#include <array>
#include <deque>
#include <map>
#include <vector>
//#include <string_view>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <strstream>
// using namespace ngtcp2;
/*      Client                                             Server

       ClientHello
      (0-RTT Application Data)  -------->
                                                     ServerHello
                                            {EncryptedExtensions}
                                                       {Finished}
                                <--------      [Application Data]
      {Finished}                -------->

      [Application Data]        <------->      [Application Data]

       () Indicates messages protected by early data (0-RTT) keys
       {} Indicates messages protected using handshake keys
       [] Indicates messages protected using application data
          (1-RTT) keys

                    Figure 1: TLS Handshake with 0-RTT
  Data is protected using a number of encryption levels:

   o  Initial Keys

   o  Early Data (0-RTT) Keys

   o  Handshake Keys

   o  Application Data (1-RTT) Keys
*/
/*Figure 3 summarizes the exchange between QUIC and TLS for both client
   and server.  Each arrow is tagged with the encryption level used for
   that transmission.

   Client                                                    Server

   Get Handshake
                        Initial ------------->
                                                 Handshake Received
   Install tx 0-RTT Keys
                        0-RTT --------------->
                                                      Get Handshake
                        <------------- Initial
   Handshake Received
   Install Handshake keys
                                              Install rx 0-RTT keys
                                             Install Handshake keys
                                                      Get Handshake
                        <----------- Handshake
   Handshake Received
                                              Install tx 1-RTT keys
                        <--------------- 1-RTT
   Get Handshake
   Handshake Complete
                        Handshake ----------->
                                                 Handshake Received
                                              Install rx 1-RTT keys
                                                 Handshake Complete
   Install 1-RTT keys
                        1-RTT --------------->
                                                      Get Handshake
                        <--------------- 1-RTT
   Handshake Received

            Figure 3: Interaction Summary between QUIC and TLS

   Figure 3 shows the multiple packets that form a single "flight" of
   messages being processed individually, to show what incoming messages
   trigger different actions.  New handshake messages are requested
   after all incoming packets have been processed.  This process might
   vary depending on how QUIC implementations and the packets they
   receive are structured.
*/
// Quic 包的大小应该不大于MTU，以避免ip 分片。当前的Quic实现在ipv6环境每个包
// 最大限制为1350的字节，ipv4环境下为1370，这两个限制都不包含ip 和 udp 头。

// tx是发送(transport),rx是接收(receive)

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

inline char lowcase(char c) {
  constexpr static unsigned char tbl[] = {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
      15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
      30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
      45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
      60,  61,  62,  63,  64,  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
      'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
      'z', 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
      105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
      120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
      135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
      150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
      165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
      180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
      195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
      210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
      225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
      240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
      255,
  };
  return tbl[static_cast<unsigned char>(c)];
}

struct CaseCmp {
  bool operator()(char lhs, char rhs) const {
    return lowcase(lhs) == lowcase(rhs);
  }
};

template <typename InputIterator1, typename InputIterator2>
bool istarts_with(InputIterator1 first1, InputIterator1 last1,
                  InputIterator2 first2, InputIterator2 last2) {
  if (last1 - first1 < last2 - first2) {
    return false;
  }
  return std::equal(first2, last2, first1, CaseCmp());
}

template <typename S, typename T>
bool istarts_with(const S &a, const T &b) {
  return istarts_with(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, typename CharT, size_t N>
bool istarts_with_l(const T &a, const CharT (&b)[N]) {
  return istarts_with(a.begin(), a.end(), b, b + N - 1);
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
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch())
      .count();
// #ifdef WIN32
// 	return GetTickCount();
// #else
// 	struct timespec ts;
// 	clock_gettime(CLOCK_MONOTONIC, &ts);
// 	return (ts.tv_sec * NGTCP2_SECONDS + ts.tv_nsec);
// #endif//

  // struct timeval tv;
  // gettimeofday (&tv, 0);
  // return tv.tv_sec * NGTCP2_SECONDS + tv.tv_usec * NGTCP2_MICROSECONDS;
}

template <class T, class TManager, class TSocket, class TBase>
class QuicHandlerBaseT : public ConnectionT<TSocket, TaskSocketT<TBase>>,
                         public std::enable_shared_from_this<T> {
  typedef QuicHandlerBaseT<T, TManager, TSocket, TBase> This;
  typedef ConnectionT<TSocket, TaskSocketT<TBase>> Base;
public:
  typedef typename Base::TaskInfo TaskInfo;
 protected:
  TManager *manager_;
  std::shared_ptr<TSocket> sock_ptr_;
  Address remote_addr_;
  std::uniform_int_distribution<> dis_;
  ngtcp2_cid scid_;
  ngtcp2_cid rcid_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  size_t max_pktlen_;
  struct Buffer {
    Buffer(const uint8_t *data, size_t datalen)
        : buf{data, data + datalen}, begin(buf.data()), tail(begin + datalen) {}
    explicit Buffer(size_t datalen)
        : buf(datalen), begin(buf.data()), tail(begin) {}

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
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  QUICError last_error_ = {QUICErrorType::Transport, 0};
  std::shared_ptr<TaskInfo> timer_;
  std::shared_ptr<TaskInfo> rttimer_;

 public:
  QuicHandlerBaseT(TManager *manager, std::shared_ptr<TSocket> sock_ptr,
                   SSL_CTX *ssl_ctx)
      : Base(sock_ptr.get()),
        sock_ptr_(sock_ptr),
        manager_(manager),
        dis_(0),
        scid_{},
        rcid_{},
        ssl_ctx_(ssl_ctx),
        ssl_(nullptr),
        max_pktlen_(0),
        crypto_{},
        conn_(nullptr),
        nkey_update_(0),
        sendbuf_{NGTCP2_MAX_PKTLEN_IPV4}
  // last_error_(QUICErrorType::Transport, 0)
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

  const ngtcp2_cid *scid() const { return &scid_; }

  const ngtcp2_cid *rcid() const { return &rcid_; }

  ngtcp2_conn *get_conn() const { return conn_; }

  void update_remote_addr(const ngtcp2_addr *addr) {
    remote_addr_.len = addr->addrlen;
    memcpy(&remote_addr_.su, addr->addr, addr->addrlen);
  }

  void set_tls_alert(uint8_t alert) { last_error_ = quic_err_tls(alert); }

  int update_key(uint8_t *rx_secret, uint8_t *tx_secret, uint8_t *rx_key,
                 uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
                 const uint8_t *current_rx_secret,
                 const uint8_t *current_tx_secret, size_t secretlen) {
    if (IsDebug()) {
      std::cerr << "Updating traffic key" << std::endl;
    }

    auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn_);
    auto aead = &crypto_ctx->aead;
    auto keylen = ngtcp2_crypto_aead_keylen(aead);
    auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

    ++this->nkey_update_;

    if (ngtcp2_crypto_update_key(conn_, rx_secret, tx_secret, rx_key, rx_iv,
                                 tx_key, tx_iv, current_rx_secret,
                                 current_tx_secret, secretlen) != 0) {
      return -1;
    }

    // if (!config.quiet && config.show_secret) {
    //   std::cerr << "application_traffic rx secret " << nkey_update_ <<
    //   std::endl; debug::print_secrets(rx_secret, secretlen, rx_key, keylen,
    //   rx_iv, ivlen); std::cerr << "application_traffic tx secret " <<
    //   nkey_update_ << std::endl; debug::print_secrets(tx_secret, secretlen,
    //   tx_key, keylen, tx_iv, ivlen);
    // }

    return 0;
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

  void OnTimer()
  {

  }

  void OnRTTimer()
  {
    
  }

  void SetTimer(size_t millis) {
    T* pT = static_cast<T*>(this);
    if(timer_) {
      Cancel(timer_);
    }
    timer_ = Post(millis, std::bind(&T::OnTimer,pT));
  }

  void KillTimer()
  {
    if(timer_) {
      Cancel(timer_);
      timer_.reset();
    }
  }

  void SetRTTimer() {
    T* pT = static_cast<T*>(this);
    if(rttimer_) {
      Cancel(rttimer_);
    }
    auto expiry = ngtcp2_conn_get_expiry(conn_);
    auto now = timestamp();
    size_t millis = 0;
    if(expiry > now) {
      millis = (expiry - now) / NGTCP2_MILLISECONDS;
    }
    rttimer_ = Post(millis, std::bind(&T::OnRTTimer,pT));
  }

  void KillRTTimer()
  {
    if(rttimer_) {
      Cancel(rttimer_);
      rttimer_.reset();
    }
  }

  void reset_idle_timer() {
    auto now = timestamp();
    auto idle_expiry = ngtcp2_conn_get_idle_expiry(conn_);
    ngtcp2_tstamp millis = 0;
    if(idle_expiry > now) {
      millis = (idle_expiry - now) / NGTCP2_MILLISECONDS;
    }
    SetTimer(millis);
    if (IsDebug()) {
        std::cerr << "Set idle timer=" << std::fixed << millis << "ms"
                  << std::defaultfloat << std::endl;
    }   
  }

  int on_read(std::shared_ptr<TSocket> ep, const sockaddr *sa, socklen_t salen,
              uint8_t *data, size_t datalen) {
    sock_ptr_ = ep;
    this->remote_addr_.len = salen;
    memcpy(&this->remote_addr_.su.sa, sa, salen);
    auto path = ngtcp2_path{
        {ep->local_addr_.len, reinterpret_cast<uint8_t *>(&ep->local_addr_.su.sa)},
        {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
    auto rv = ngtcp2_conn_read_pkt(conn_, &path, data, datalen, timestamp());
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
      switch (rv) {
        case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
        case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
        case NGTCP2_ERR_TRANSPORT_PARAM:
          // If rv indicates transport_parameters related error, we should
          // send TRANSPORT_PARAMETER_ERROR even if last_error_.code is
          // already set.  This is because OpenSSL might set Alert.
          last_error_ = quic_err_transport(rv);
          break;
        default:
          if (!last_error_.code) {
            last_error_ = quic_err_transport(rv);
          }
      }
      return -1;
    }
    return 0;
  }

  int on_write() { return 0; }

  int send_packet() {
    this->manager_->send_packet(this->sock_ptr_, this->sendbuf_.rpos(), this->sendbuf_.size(),
                                 &this->remote_addr_.su.sa, this->remote_addr_.len);
    this->sendbuf_.reset();
    return NETWORK_ERR_OK;
  }
};

template <class T, class TSocket, class THandlerSet>
class QuicManagerBaseT : public SocketManagerT<THandlerSet> {
  typedef SocketManagerT<THandlerSet> Base;

 public:
  using Buffer = typename TSocket::Buffer;
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
  //
  std::map<std::string, std::shared_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;

 public:
  QuicManagerBaseT(int max_handlerset_count) : Base(max_handlerset_count) {}

  ~QuicManagerBaseT() {}

  bool Start() { return Base::Start(); }

  void Stop() {
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

  static inline std::string make_cid_key(const ngtcp2_cid *cid) {
    return std::string(cid->data, cid->data + cid->datalen);
  }

  static inline std::string make_cid_key(const uint8_t *cid, size_t cidlen) {
    return std::string(cid, cid + cidlen);
  }

  inline void associate_cid(const ngtcp2_cid *cid, Handler *h) {
    handlers_.emplace(make_cid_key(cid), h->shared_from_this());
    ctos_.emplace(make_cid_key(cid), make_cid_key(h->scid()));
  }

  inline void dissociate_cid(const ngtcp2_cid *cid) {
    handlers_.erase(make_cid_key(cid));
    ctos_.erase(make_cid_key(cid));
  }

  void remove(const Handler *h) {
    ctos_.erase(make_cid_key(h->rcid()));

    auto conn = h->get_conn();
    std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(conn));
    ngtcp2_conn_get_scid(conn, cids.data());

    for (auto &cid : cids) {
      ctos_.erase(make_cid_key(&cid));
    }

    this->handlers_.erase(make_cid_key(h->scid()));
  }

  int send_packet(std::shared_ptr<TSocket> ep, const uint8_t *data,
                  size_t datalen, const sockaddr *sa, socklen_t salen,
                  size_t gso_size = 0) {
    if (packet_lost(tx_loss_prob)) {
      if (IsDebug()) {
        std::cerr << "** Simulated outgoing packet loss **" << std::endl;
      }
      return NETWORK_ERR_OK;
    }

    typename TSocket::Buffer buf(data, datalen, sa, salen);
    ep->Post(
        [ep, buf]() { ep->SendBuf(buf); });

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
  // using typename TBase::Buffer;
  Address local_addr_;

 public:
  QuickSocketT() {}

  ~QuickSocketT() {}

  SOCKET Open(int nSockAf, int nSockType, int nSockProtocol) {
    SOCKET sock = Base::Open(nSockAf, nSockType, nSockProtocol);
    if (sock != INVALID_SOCKET) {
      local_addr_.len = sizeof(local_addr_.su.storage);
      GetSockName(&local_addr_.su.sa, &local_addr_.len);
    }
    return sock;
  }
};

}  // namespace XSocket

#endif  //_H_XQUIC_IMPL_H_
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

enum network_error {
  NETWORK_ERR_OK = 0,
  NETWORK_ERR_FATAL = -10,
  NETWORK_ERR_SEND_BLOCKED = -11,
  NETWORK_ERR_CLOSE_WAIT = -12,
  NETWORK_ERR_RETRY = -13,
  NETWORK_ERR_DROP_CONN = -14,
};

namespace {
constexpr char LOWER_XDIGITS[] = "0123456789abcdef";
} // namespace

inline std::string format_hex(uint8_t c) {
  std::string s;
  s.resize(2);

  s[0] = LOWER_XDIGITS[c >> 4];
  s[1] = LOWER_XDIGITS[c & 0xf];

  return s;
}

inline std::string format_hex(const uint8_t *s, size_t len) {
  std::string res;
  res.resize(len * 2);

  for (size_t i = 0; i < len; ++i) {
    auto c = s[i];

    res[i * 2] = LOWER_XDIGITS[c >> 4];
    res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

inline std::string format_hex(const std::string &s) {
  return format_hex(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

 template<class TSocket, class TSockAddr = SOCKADDR_IN>
 class QuickHandler : public ConnectionT<TSocket>
 {
	 typedef ConnectionT<TSocket> Base;
public:
  typedef TSockAddr SockAddr;
 protected:
  SockAddr remote_addr_;
  SSL_CTX *ssl_ctx_ ;
  SSL *ssl_;
  //Crypto crypto_[3];
  ngtcp2_conn *conn_;
  ngtcp2_cid scid_;
  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  // draining_ becomes true when draining period starts.
  bool draining_;
 public:
	QuickHandler(SocketEx *server, SSL_CTX *ssl_ctx, const ngtcp2_cid *rcid):Base(dynamic_cast<TSocket*>(server)),ssl_ctx_(ssl_ctx),ssl_(nullptr)
  //, crypto_{}
	, conn_(nullptr)
	, scid_{}
    , pscid_{}
    , rcid_(*rcid)
	, draining_(false)
	{
	}

	~QuickHandler() 
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
	
const ngtcp2_cid *scid() const { return &scid_; }

const ngtcp2_cid *pscid() const { return &pscid_; }

const ngtcp2_cid *rcid() const { return &rcid_; }

const SockAddr &remote_addr() const { return remote_addr_; }

ngtcp2_conn *conn() const { return conn_; }

	
int init(const SockAddr& sa,
                  const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                  const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
                  uint32_t version) 
{
	remote_addr_ = sa;				  

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);
  //SSL_set_quic_early_data_enabled(ssl_, 1);

//   auto callbacks = ngtcp2_conn_callbacks{
//       nullptr, // client_initial
//       ::recv_client_initial,
//       ::recv_crypto_data,
//       ::handshake_completed,
//       nullptr, // recv_version_negotiation
//       ngtcp2_crypto_encrypt_cb,
//       ngtcp2_crypto_decrypt_cb,
//       do_hp_mask,
//       ::recv_stream_data,
//       acked_crypto_offset,
//       ::acked_stream_data_offset,
//       stream_open,
//       stream_close,
//       nullptr, // recv_stateless_reset
//       nullptr, // recv_retry
//       nullptr, // extend_max_streams_bidi
//       nullptr, // extend_max_streams_uni
//       rand,
//       get_new_connection_id,
//       remove_connection_id,
//       ::update_key,
//       path_validation,
//       nullptr, // select_preferred_addr
//       ::stream_reset,
//       ::extend_max_remote_streams_bidi,
//       nullptr, // extend_max_remote_streams_uni,
//       ::extend_max_stream_data,
//   };

//   auto dis = std::uniform_int_distribution<>(0);

//   scid_.datalen = NGTCP2_SV_SCIDLEN;
//   std::generate(scid_.data, scid_.data + scid_.datalen,
//                 [&dis]() { return dis(randgen)%255; });

//   ngtcp2_settings settings;
//   ngtcp2_settings_default(&settings);
//   settings.log_printf = config.quiet ? nullptr : debug::log_printf;
//   settings.initial_ts = util::timestamp(loop_);
//   settings.token = ngtcp2_vec{const_cast<uint8_t *>(token), tokenlen};
//   if (!config.qlog_dir.empty()) {
//     auto path = std::string{config.qlog_dir};
//     path += '/';
//     path += util::format_hex(scid_.data, scid_.datalen);
//     path += ".qlog";
//     qlog_ = fopen(path.c_str(), "w");
//     if (qlog_ == nullptr) {
//       std::cerr << "Could not open qlog file " << path << ": "
//                 << strerror(errno) << std::endl;
//       return -1;
//     }
//     settings.qlog.write = ::write_qlog;
//     settings.qlog.odcid = *scid;
//   }
//   auto &params = settings.transport_params;
//   params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
//   params.initial_max_stream_data_bidi_remote =
//       config.max_stream_data_bidi_remote;
//   params.initial_max_stream_data_uni = config.max_stream_data_uni;
//   params.initial_max_data = config.max_data;
//   params.initial_max_streams_bidi = config.max_streams_bidi;
//   params.initial_max_streams_uni = config.max_streams_uni;
//   params.max_idle_timeout = config.timeout;
//   params.stateless_reset_token_present = 1;
//   params.active_connection_id_limit = 7;

//   if (ocid) {
//     params.original_connection_id = *ocid;
//     params.original_connection_id_present = 1;
//   }

//   std::generate(std::begin(params.stateless_reset_token),
//                 std::end(params.stateless_reset_token),
//                 [&dis]() { return dis(randgen); });

//   if (config.preferred_ipv4_addr.len || config.preferred_ipv6_addr.len) {
//     params.preferred_address_present = 1;
//     if (config.preferred_ipv4_addr.len) {
//       auto &dest = params.preferred_address.ipv4_addr;
//       const auto &addr = config.preferred_ipv4_addr;
//       assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
//       memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
//       params.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
//     }
//     if (config.preferred_ipv6_addr.len) {
//       auto &dest = params.preferred_address.ipv6_addr;
//       const auto &addr = config.preferred_ipv6_addr;
//       assert(sizeof(dest) == sizeof(addr.su.in6.sin6_addr));
//       memcpy(&dest, &addr.su.in6.sin6_addr, sizeof(dest));
//       params.preferred_address.ipv6_port = htons(addr.su.in6.sin6_port);
//     }

//     auto &token = params.preferred_address.stateless_reset_token;
//     std::generate(std::begin(token), std::end(token),
//                   [&dis]() { return dis(randgen); });

//     pscid_.datalen = NGTCP2_SV_SCIDLEN;
//     std::generate(pscid_.data, pscid_.data + pscid_.datalen,
//                   [&dis]() { return dis(randgen); });
//     params.preferred_address.cid = pscid_;
//   }

//   auto path = ngtcp2_path{
//       {ep.addr.len,
//        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&ep.addr.su)),
//        const_cast<Endpoint *>(&ep)},
//       {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
//   if (auto rv = ngtcp2_conn_server_new(&conn_, dcid, &scid_, &path, version,
//                                        &callbacks, &settings, nullptr, this);
//       rv != 0) {
//     std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
//     return -1;
//   }

//   std::array<uint8_t, 512> buf;

//   auto nwrite = ngtcp2_encode_transport_params(
//       buf.data(), buf.size(), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
//       &params);
//   if (nwrite < 0) {
//     std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
//               << std::endl;
//     return -1;
//   }

//   if (SSL_set_quic_transport_params(ssl_, buf.data(), nwrite) != 1) {
//     std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
//     return -1;
//   }

//   ev_io_set(&wev_, endpoint_->fd, EV_WRITE);
//   ev_timer_again(loop_, &timer_);

  return 0;
}


void signal_write() {  }

bool draining() const { return draining_; }


  int on_read(const SockAddr& sa, uint8_t *data, size_t datalen)
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

/*!
 *	@brief QuickSocketT 定义.
 *
 *	封装QuickSocketT，实现Udp Quick收发数据功能
 */
template<class TBase>
class QuickSocketT : public TBase
{
	typedef QuickSocketT<TBase> This;
	typedef TBase Base;
protected:
  	SSL_CTX *ssl_ctx_;
public:
	QuickSocketT()
	{
			
	}

	~QuickSocketT() 
	{
		
	}
};

/*!
 *	@brief QuickServerSocketT 定义.
 *
 *	封装QuickServerSocketT，实现Quick服务端Socket
 */
template<class TBase, class THandler>
class QuickServerSocketT : public QuickSocketT<TBase>
{
	typedef QuickServerSocketT<TBase,THandler> This;
	typedef QuickSocketT<TBase> Base;
public:
	typedef typename Base::SockAddr SockAddr;
  typedef typename Base::UdpBuffer UdpBuffer;
	typedef THandler Handler;
protected:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
public:
	QuickServerSocketT()
	{
			
	}

	~QuickServerSocketT() 
	{
		
	}

protected:
  // 
	static std::mt19937 randgen;
  // tx_loss_prob is probability of losing outgoing packet.
  static double tx_loss_prob;
  // rx_loss_prob is probability of losing incoming packet.
  static double rx_loss_prob;
  // validate_addr is true if server requires address validation.
  static bool validate_addr;
  // static_secret is used to derive keying materials for Retry and
  // Stateless Retry token.
  static std::array<uint8_t, 32> static_secret;

	static bool packet_lost(double prob) {
		auto p = std::uniform_real_distribution<>(0, 1)(randgen);
		return p < prob;
	}

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

inline int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
                             size_t &ivlen, const uint8_t *rand_data,
                             size_t rand_datalen) {
  std::array<uint8_t, 32> secret;

  if (ngtcp2_crypto_hkdf_extract(
          secret.data(), &token_md_, static_secret.data(),
          static_secret.size(), rand_data, rand_datalen) != 0) {
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

static inline void generate_rand_data(uint8_t *buf, size_t len) {
  auto dis = std::uniform_int_distribution<>(0);
  std::generate_n(buf, len, [&dis]() { return dis(randgen)%255; });
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

int send_version_negotiation(uint32_t version, const uint8_t *dcid,size_t dcidlen, const uint8_t *scid,size_t scidlen, const SockAddr& sa) {
	uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
	uint32_t sv[2] = {0};

	sv[0] = generate_reserved_version((const sockaddr *)&sa, sizeof(sa), version);
	sv[1] = NGTCP2_PROTO_VER;

	auto nwrite = ngtcp2_pkt_write_version_negotiation(
		buf, NGTCP2_MAX_PKTLEN_IPV4,
		std::uniform_int_distribution<>(0)(randgen)%255,
		dcid, dcidlen, scid, scidlen, sv, 2);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_version_negotiation: "
				<< ngtcp2_strerror(nwrite) << std::endl;
		return -1;
	}

	SendBuf((const char*)buf, nwrite, sa);

	return 0;
	}

int send_retry(const ngtcp2_pkt_hd *chd, const SockAddr& sa) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;
  
  auto rv = getnameinfo((const sockaddr *)&sa, sizeof(sa), host.data(), host.size(), port.data(),
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

  if (generate_token(token.data(), tokenlen, (const sockaddr *)&sa, sizeof(sa), &chd->dcid) != 0) {
    return -1;
  }

  if (IsDebug()) {
    std::cerr << "Generated address validation token:" << std::endl;
    //util::hexdump(stderr, token.data(), tokenlen);
  }

  UdpBuffer buf = {0};
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

  SendBuf((const char*)buf, nwrite, sa);

  return 0;
}

int send_stateless_connection_close(const ngtcp2_pkt_hd *chd, const SockAddr& sa) {
  uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};

  auto nwrite = ngtcp2_crypto_write_connection_close(
      buf, sizeof(buf), &chd->scid, &chd->dcid, NGTCP2_INVALID_TOKEN);
  if (nwrite < 0) {
    std::cerr << "ngtcp2_crypto_write_connection_close failed" << std::endl;
    return -1;
  }

  SendBuf((const char*)buf, nwrite, sa);

  return 0;
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
	virtual int ParseBuf(const char* buf, int & nread, const SockAddr & sa) { 
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

    if (packet_lost(rx_loss_prob)) {
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
        send_version_negotiation(version, scid, scidlen, dcid, dcidlen, sa);
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
          send_version_negotiation(hd.version, hd.scid.data, hd.scid.datalen,
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
              send_retry(&hd, sa);
              return SOCKET_PACKET_FLAG_COMPLETE;
            }
            if (verify_token(&ocid, &hd, (const sockaddr *)&sa, sizeof(sa)) != 0) {
              send_stateless_connection_close(&hd, sa);
              return SOCKET_PACKET_FLAG_COMPLETE;
            }
            pocid = &ocid;
          }
          break;
        case NGTCP2_PKT_0RTT:
          send_retry(&hd, sa);
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        auto h = std::unique_ptr<Handler>(new Handler(this, Base::ssl_ctx_, &hd.dcid));
        if (h->init(sa, &hd.scid, &hd.dcid, pocid, hd.token,
                    hd.tokenlen, hd.version) != 0) {
          return SOCKET_PACKET_FLAG_COMPLETE;
        }

        switch (h->on_read(sa, (uint8_t *)buf, nread)) {
        case 0:
          break;
        case NETWORK_ERR_RETRY:
          send_retry(&hd, sa);
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

    rv = h->on_read(sa, (uint8_t *)buf, nread);
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

template<class TBase, class THandler>
std::mt19937 QuickServerSocketT<TBase,THandler>::randgen = std::mt19937(/*std::random_device()*/);
template<class TBase, class THandler>
double QuickServerSocketT<TBase,THandler>::tx_loss_prob = 0.5;
template<class TBase, class THandler>
double QuickServerSocketT<TBase,THandler>::rx_loss_prob = 0.5;
template<class TBase, class THandler>
bool QuickServerSocketT<TBase,THandler>::validate_addr = true;
template<class TBase, class THandler>
std::array<uint8_t, 32> QuickServerSocketT<TBase,THandler>::static_secret;

// /*!
//  *	@brief QuickClientSocketT 定义.
//  *
//  *	封装QuickClientSocketT，实现Quick客户端Socket
//  */
// template<class TBase, class THandler>
// class QuickClientSocketT : public TBase
// {
// 	typedef QuickClientSocketT<TBase,THandler> This;
// 	typedef TBase Base;
// public:
// 	typedef THandler Handler;
// protected:
// 	Address local_addr_;
// 	Address remote_addr_;
// 	size_t max_pktlen_;
// 	ev_io wev_;
// 	ev_io rev_;
// 	ev_timer timer_;
// 	ev_timer rttimer_;
// 	ev_timer change_local_addr_timer_;
// 	ev_timer key_update_timer_;
// 	ev_timer delay_stream_timer_;
// 	ev_signal sigintev_;
// 	struct ev_loop *loop_;
// 	SSL_CTX *ssl_ctx_;
// 	SSL *ssl_;
// 	int fd_;
// 	std::map<int64_t, std::unique_ptr<Stream>> streams_;
// 	Crypto crypto_[3];
// 	FILE *qlog_;
// 	ngtcp2_conn *conn_;
// 	nghttp3_conn *httpconn_;
// 	// addr_ is the server host address.
// 	const char *addr_;
// 	// port_ is the server port.
// 	const char *port_;
// 	QUICError last_error_;
// 	// common buffer used to store packet data before sending
// 	Buffer sendbuf_;
// 	// nstreams_done_ is the number of streams opened.
// 	uint64_t nstreams_done_;
// 	// nkey_update_ is the number of key update occurred.
// 	size_t nkey_update_;
// 	uint32_t version_;
// 	// early_data_ is true if client attempts to do 0RTT data transfer.
// 	bool early_data_;
// 	// should_exit_ is true if client should exit rather than waiting
// 	// for timeout.
// 	bool should_exit_;
// public:
// 	QuickClientSocketT()
// 	{
			
// 	}

// 	~QuickClientSocketT() 
// 	{
		
// 	}
// };

}

#endif//_H_XHTTP_IMPL_H_
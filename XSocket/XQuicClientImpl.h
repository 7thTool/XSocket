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
#ifndef _H_XQUICCLIENT_IMPL_H_
#define _H_XQUICCLIENT_IMPL_H_

#include "XQuicImpl.h"

namespace XSocket {

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

}

#endif//_H_XQUICCLIENT_IMPL_H_
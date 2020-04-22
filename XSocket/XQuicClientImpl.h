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

#include <fstream>

#include "XQuicImpl.h"

namespace XSocket {

template <class T, class TManager, class TSocket, class TBase>
class QuicClientHandlerT
    : public QuicHandlerBaseT<T, TManager, TSocket, TBase> {
  typedef QuicClientHandlerT<T, TManager, TSocket, TBase> This;
  typedef QuicHandlerBaseT<T, TManager, TSocket, TBase> Base;

 protected:
  std::string host_;
  size_t max_pktlen_;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  std::string tp_file_;
  // early_data_ is true if client attempts to do 0RTT data transfer.
  bool early_data_;

 public:
  QuicClientHandlerT(TManager *manager, std::shared_ptr<TSocket> sock_ptr, SSL_CTX *ssl_ctx)
      : Base(manager, sock_ptr, ssl_ctx) {
    // auto dis = std::uniform_int_distribution<uint8_t>(
    //     0, std::numeric_limits<uint8_t>::max());
    auto generate_cid = [&dis = this->dis_](ngtcp2_cid &cid, size_t len) {
      cid.datalen = len;
      std::generate(std::begin(cid.data), std::begin(cid.data) + cid.datalen,
                    [&dis]() { return dis(randgen); });
    };

    generate_cid(this->scid_, 17);
    // if (config.dcid.datalen == 0) {
    generate_cid(this->rcid_, 18);
    //} else {
    //  dcid = config.dcid;
    //}
  }

  int read_transport_params(const char *path, ngtcp2_transport_params *params) {
    std::ifstream f(path);
    if (!f) {
      return -1;
    }

    for (std::string line; std::getline(f, line);) {
      if (istarts_with_l(line, "initial_max_streams_bidi=")) {
        params->initial_max_streams_bidi = strtoul(
            line.c_str() + str_size("initial_max_streams_bidi="), nullptr, 10);
      } else if (istarts_with_l(line, "initial_max_streams_uni=")) {
        params->initial_max_streams_uni = strtoul(
            line.c_str() + str_size("initial_max_streams_uni="), nullptr, 10);
      } else if (istarts_with_l(line, "initial_max_stream_data_bidi_local=")) {
        params->initial_max_stream_data_bidi_local = strtoul(
            line.c_str() + str_size("initial_max_stream_data_bidi_local="),
            nullptr, 10);
      } else if (istarts_with_l(line, "initial_max_stream_data_bidi_remote=")) {
        params->initial_max_stream_data_bidi_remote = strtoul(
            line.c_str() + str_size("initial_max_stream_data_bidi_remote="),
            nullptr, 10);
      } else if (istarts_with_l(line, "initial_max_stream_data_uni=")) {
        params->initial_max_stream_data_uni =
            strtoul(line.c_str() + str_size("initial_max_stream_data_uni="),
                    nullptr, 10);
      } else if (istarts_with_l(line, "initial_max_data=")) {
        params->initial_max_data =
            strtoul(line.c_str() + str_size("initial_max_data="), nullptr, 10);
      }
    }

    return 0;
  }

  int init(std::shared_ptr<TSocket> ep, const Address &remote_addr, const std::string &host,
           u_short port) {
    T *pT = static_cast<T *>(this);
    this->remote_addr_ = remote_addr;
    host_ = host;

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
        // int client_initial
        [](ngtcp2_conn *conn, void *user_data) {
          auto c = static_cast<T *>(user_data);

          if (c->recv_crypto_data(NGTCP2_CRYPTO_LEVEL_INITIAL, nullptr, 0) !=
              0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // recv_client_initial
        // int recv_crypto_data
        [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level, uint64_t offset,
           const uint8_t *data, size_t datalen, void *user_data) {
          //   if (!config.quiet && !config.no_quic_dump) {
          //     debug::print_crypto_data(crypto_level, data, datalen);
          //   }

          auto c = static_cast<T *>(user_data);

          if (c->recv_crypto_data(crypto_level, data, datalen) != 0) {
            auto err = ngtcp2_conn_get_tls_error(conn);
            if (err) {
              return err;
            }
            return (int)NGTCP2_ERR_CRYPTO;
          }

          return 0;
        },
        // int handshake_completed
        [](ngtcp2_conn *conn, void *user_data) {
          auto c = static_cast<T *>(user_data);

          //   if (!config.quiet) {
          //     debug::handshake_completed(conn, user_data);
          //   }

          if (c->handshake_completed() != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // recv_version_negotiation
        // int ngtcp2_crypto_encrypt_cb
        [](uint8_t *dest, const ngtcp2_crypto_aead *aead,
           const uint8_t *plaintext, size_t plaintextlen, const uint8_t *key,
           const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
           size_t adlen) {
          if (ngtcp2_crypto_encrypt(dest, aead, plaintext, plaintextlen, key,
                                    nonce, noncelen, ad, adlen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // int ngtcp2_crypto_encrypt_cb
        [](uint8_t *dest, const ngtcp2_crypto_aead *aead,
           const uint8_t *plaintext, size_t plaintextlen, const uint8_t *key,
           const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
           size_t adlen) {
          if (ngtcp2_crypto_encrypt(dest, aead, plaintext, plaintextlen, key,
                                    nonce, noncelen, ad, adlen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // int do_hp_mask
        [](uint8_t *dest, const ngtcp2_crypto_cipher *hp, const uint8_t *hp_key,
           const uint8_t *sample) {
          if (ngtcp2_crypto_hp_mask(dest, hp, hp_key, sample) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          //   if (!config.quiet && config.show_secret) {
          //     debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample,
          //     NGTCP2_HP_SAMPLELEN);
          //   }

          return 0;
        },
        // int recv_stream_data
        [](ngtcp2_conn *conn, int64_t stream_id, int fin, uint64_t offset,
           const uint8_t *data, size_t datalen, void *user_data,
           void *stream_user_data) {
          //   if (!config.quiet && !config.no_quic_dump) {
          //     debug::print_stream_data(stream_id, data, datalen);
          //   }

          auto c = static_cast<T *>(user_data);

          if (c->recv_stream_data(stream_id, fin, data, datalen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        // int acked_crypto_offset
        [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level, uint64_t offset,
           size_t datalen, void *user_data) {
          auto c = static_cast<T *>(user_data);
          c->remove_tx_crypto_data(crypto_level, offset, datalen);

          return 0;
        },
        // int acked_stream_data_offset
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t offset,
           size_t datalen, void *user_data, void *stream_user_data) {
          auto c = static_cast<T *>(user_data);
          if (c->acked_stream_data_offset(stream_id, datalen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        nullptr,  // stream_open
        // int stream_close
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
           void *user_data, void *stream_user_data) {
          auto c = static_cast<T *>(user_data);

          if (c->on_stream_close(stream_id, app_error_code) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // recv_stateless_reset
        // int recv_retry
        [](ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
           const ngtcp2_pkt_retry *retry, void *user_data) {
          // Re-generate handshake secrets here because connection ID might
          // change.
          auto c = static_cast<T *>(user_data);

          c->on_recv_retry();

          return 0;
        },
        // int extend_max_streams_bidi
        [](ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
          auto c = static_cast<T *>(user_data);

          if (c->on_extend_max_streams() != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // extend_max_streams_uni
        // int rand
        [](ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
           ngtcp2_rand_ctx ctx, void *user_data) {
          auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
          std::generate(dest, dest + destlen,
                        [&dis]() { return dis(randgen); });
          return 0;
        },
        // int get_new_connection_id
        [](ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
           void *user_data) {
          auto c = static_cast<T *>(user_data);
          return c->get_new_connection_id(conn, cid, token, cidlen);
        },
        // int remove_connection_id
        [](ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data) {
          return 0;
        },
        // int update_key
        [](ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
           uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
           const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
           size_t secretlen, void *user_data) {
          auto c = static_cast<T *>(user_data);

          if (c->update_key(rx_secret, tx_secret, rx_key, rx_iv, tx_key, tx_iv,
                            current_rx_secret, current_tx_secret,
                            secretlen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        // int path_validation
        [](ngtcp2_conn *conn, const ngtcp2_path *path,
           ngtcp2_path_validation_result res, void *user_data) {
          //   if (!config.quiet) {
          //     debug::path_validation(path, res);
          //   }
          return 0;
        },
        // int select_preferred_address
        [](ngtcp2_conn *conn, ngtcp2_addr *dest,
           const ngtcp2_preferred_addr *paddr, void *user_data) {
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
        // int stream_reset
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
           uint64_t app_error_code, void *user_data, void *stream_user_data) {
          auto c = static_cast<T *>(user_data);

          if (c->on_stream_reset(stream_id) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // extend_max_remote_streams_bidi,
        nullptr,  // extend_max_remote_streams_uni,
        // int extend_max_stream_data
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data,
           void *user_data, void *stream_user_data) {
          auto c = static_cast<T *>(user_data);
          if (c->extend_max_stream_data(stream_id, max_data) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.log_printf = IsDebug() ? printf : nullptr;
    //   if (config.qlog_file) {
    //     qlog_ = fopen(config.qlog_file, "w");
    //     if (qlog_ == nullptr) {
    //       std::cerr << "Could not open qlog file " << config.qlog_file << ":
    //       "
    //                 << strerror(errno) << std::endl;
    //       return -1;
    //     }
    //     settings.qlog.write = ::write_qlog;
    //     settings.qlog.odcid = dcid;
    //   }
    settings.initial_ts = timestamp();
    auto &params = settings.transport_params;
    params.initial_max_stream_data_bidi_local =
        this->manager_->max_stream_data_bidi_local;
    params.initial_max_stream_data_bidi_remote =
        this->manager_->max_stream_data_bidi_remote;
    params.initial_max_stream_data_uni = this->manager_->max_stream_data_uni;
    params.initial_max_data = this->manager_->max_data;
    params.initial_max_streams_bidi = this->manager_->max_streams_bidi;
    params.initial_max_streams_uni = this->manager_->max_streams_uni;
    params.max_idle_timeout = this->manager_->timeout;
    params.active_connection_id_limit = 7;

    auto path = ngtcp2_path{
        {ep->local_addr_.len,
         const_cast<uint8_t *>(
             reinterpret_cast<const uint8_t *>(&ep->local_addr_.su))},
        {remote_addr.len,
         const_cast<uint8_t *>(
             reinterpret_cast<const uint8_t *>(&remote_addr.su))}};
    auto rv = ngtcp2_conn_client_new(&this->conn_, &this->rcid_, &this->scid_, &path,
                                     this->manager_->version, &callbacks,
                                     &settings, nullptr, this);
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_client_new: " << ngtcp2_strerror(rv)
                << std::endl;
      return -1;
    }

    if (pT->init_ssl() != 0) {
      return -1;
    }

    if (pT->setup_initial_crypto_context() != 0) {
      return -1;
    }

    if (early_data_) {
      tp_file_ = this->manager_->work_path;
      tp_file_ += "/";
      tp_file_ += host;
      ngtcp2_transport_params params;
      if (pT->read_transport_params(tp_file_.c_str(), &params) != 0) {
        std::cerr << "Could not read transport parameters from " << tp_file_
                  << std::endl;
        early_data_ = false;
      } else {
        ngtcp2_conn_set_early_remote_transport_params(this->conn_, &params);
        pT->make_stream_early();
      }
    }

    //   ev_io_start(loop_, &rev_);
    //   ev_timer_again(loop_, &timer_);

    //   ev_signal_start(loop_, &sigintev_);

    return 0;
  }

  int init_ssl() {
    if (this->ssl_) {
      SSL_free(this->ssl_);
    }

    this->ssl_ = SSL_new(this->ssl_ctx_);
    SSL_set_app_data(this->ssl_, static_cast<T*>(this));
    SSL_set_connect_state(this->ssl_);

    const uint8_t *alpn = nullptr;
    size_t alpnlen;

    switch (this->manager_->version) {
      case NGTCP2_PROTO_VER:
        alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_H3);
        alpnlen = str_size(NGTCP2_ALPN_H3);
        break;
    }
    if (alpn) {
      SSL_set_alpn_protos(this->ssl_, alpn, alpnlen);
    }

    if (numeric_host(host_.c_str())) {
      // If remote host is numeric address, just send "localhost" as SNI
      // for now.
      SSL_set_tlsext_host_name(this->ssl_, "localhost");
    } else {
      SSL_set_tlsext_host_name(this->ssl_, host_.c_str());
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

    if (SSL_set_quic_transport_params(this->ssl_, buf.data(), nwrite) != 1) {
      std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
      return -1;
    }

    if (this->manager_->session_file) {
      auto f = BIO_new_file(this->manager_->session_file, "r");
      if (f == nullptr) {
        std::cerr << "Could not read TLS session file "
                  << this->manager_->session_file << std::endl;
      } else {
        auto session = PEM_read_bio_SSL_SESSION(f, nullptr, 0, nullptr);
        BIO_free(f);
        if (session == nullptr) {
          std::cerr << "Could not read TLS session file "
                    << this->manager_->session_file << std::endl;
        } else {
          if (!SSL_set_session(this->ssl_, session)) {
            std::cerr << "Could not set session" << std::endl;
          } else if (!this->manager_->disable_early_data &&
                     SSL_SESSION_get_max_early_data(session)) {
            early_data_ = true;
            SSL_set_quic_early_data_enabled(this->ssl_, 1);
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
            this->conn_, rx_secret.data(), tx_secret.data(),
            initial_secret.data(), rx_key.data(), rx_iv.data(),
            rx_hp_key.data(), tx_key.data(), tx_iv.data(), tx_hp_key.data(),
            dcid, NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
      std::cerr << "ngtcp2_crypto_derive_and_install_initial_key() failed"
                << std::endl;
      return -1;
    }

    //   if (!config.quiet && config.show_secret) {
    //     debug::print_initial_secret(initial_secret.data(),
    //     initial_secret.size());

    //     std::cerr << "initial rx secret" << std::endl;
    //     debug::print_secrets(rx_secret.data(), rx_secret.size(),
    //     rx_key.data(),
    //                          rx_key.size(), rx_iv.data(), rx_iv.size(),
    //                          rx_hp_key.data(), rx_hp_key.size());
    //     std::cerr << "initial tx secret" << std::endl;
    //     debug::print_secrets(tx_secret.data(), tx_secret.size(),
    //     tx_key.data(),
    //                          tx_key.size(), tx_iv.data(), tx_iv.size(),
    //                          tx_hp_key.data(), tx_hp_key.size());
    //   }

    return 0;
  }

  int select_preferred_address(Address &selected_addr,
                               const ngtcp2_preferred_addr *paddr) {
    //   int af;
    //   const uint8_t *binaddr;
    //   uint16_t port;
    //   constexpr uint8_t empty_addr[] = {0, 0, 0, 0, 0, 0, 0, 0,
    //                                     0, 0, 0, 0, 0, 0, 0, 0};
    //   if (local_addr_.su.sa.sa_family == AF_INET &&
    //       memcmp(empty_addr, paddr->ipv4_addr, sizeof(paddr->ipv4_addr)) !=
    //       0) {
    //     af = AF_INET;
    //     binaddr = paddr->ipv4_addr;
    //     port = paddr->ipv4_port;
    //   } else if (local_addr_.su.sa.sa_family == AF_INET6 &&
    //              memcmp(empty_addr, paddr->ipv6_addr,
    //              sizeof(paddr->ipv6_addr)) !=
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

    //   if (auto rv = getaddrinfo(host, std::to_string(port).c_str(), &hints,
    //   &res);
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

  int write_transport_params(const char *path,
                             const ngtcp2_transport_params *params) {
    // auto f = std::ofstream(path);
    // if (!f) {
    //   return -1;
    // }

    // f << "initial_max_streams_bidi=" << params->initial_max_streams_bidi <<
    // '\n'
    //   << "initial_max_streams_uni=" << params->initial_max_streams_uni <<
    //   '\n'
    //   << "initial_max_stream_data_bidi_local="
    //   << params->initial_max_stream_data_bidi_local << '\n'
    //   << "initial_max_stream_data_bidi_remote="
    //   << params->initial_max_stream_data_bidi_remote << '\n'
    //   << "initial_max_stream_data_uni=" <<
    //   params->initial_max_stream_data_uni
    //   << '\n'
    //   << "initial_max_data=" << params->initial_max_data << '\n';

    // f.close();
    // if (!f) {
    //   return -1;
    // }

    return 0;
  }

  void on_recv_retry() { setup_initial_crypto_context(); }

int handle_error() {
  if (!this->conn_ || ngtcp2_conn_is_in_closing_period(this->conn_)) {
    return 0;
  }

  this->sendbuf_.reset();
  assert(this->sendbuf_.left() >= this->max_pktlen_);

  if (this->last_error_.type == QUICErrorType::TransportVersionNegotiation) {
    return 0;
  }

  PathStorage path;
  if (this->last_error_.type == QUICErrorType::Transport) {
    auto n = ngtcp2_conn_write_connection_close(
        this->conn_, &path.path, this->sendbuf_.wpos(), this->max_pktlen_, this->last_error_.code,
        timestamp());
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_connection_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    this->sendbuf_.push(n);
  } else {
    auto n = ngtcp2_conn_write_application_close(
        this->conn_, &path.path, this->sendbuf_.wpos(), this->max_pktlen_, this->last_error_.code,
        timestamp());
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_application_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    this->sendbuf_.push(n);
  }

  update_remote_addr(&path.path.remote);

  return send_packet();
}

void disconnect() {
  handle_error();

  //config.tx_loss_prob = 0;

  // ev_timer_stop(loop_, &delay_stream_timer_);
  // ev_timer_stop(loop_, &key_update_timer_);
  // ev_timer_stop(loop_, &change_local_addr_timer_);
  KillRTTimer();
  KillTimer();

  Close();

  this->manager_->remove(this);
}

void OnTimer() {
  if (IsDebug()) {
    std::cerr << "Timeout" << std::endl;
  }
  disconnect();
}

void OnRTTimer() {
    T* pT = static_cast<T*>(this);
  int rv;
  rv = pT->handle_expiry();
  if (rv != 0) {
    goto fail;
  }

  rv = pT->on_write();
  if (rv != 0) {
    goto fail;
  }

  return;

fail:
  switch (rv) {
  case NETWORK_ERR_SEND_BLOCKED:
    return;
  default:
    pT->disconnect();
    return;
  }
}

int handle_expiry() {
    T* pT = static_cast<T*>(this);
  auto now = timestamp();
  if (auto rv = ngtcp2_conn_handle_expiry(this->conn_, now); rv != 0) {
    std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
              << std::endl;
    this->last_error_ = quic_err_transport(NGTCP2_ERR_INTERNAL);
    pT->disconnect();
    return -1;
  }

  return 0;
}

 int on_write() { 
    T* pT = static_cast<T*>(this);
    if (this->sendbuf_.size() > 0) {
    int rv = pT->send_packet();
    if (rv != NETWORK_ERR_OK) {
      if (rv != NETWORK_ERR_SEND_BLOCKED) {
        this->last_error_ = quic_err_transport(NGTCP2_ERR_INTERNAL);
        pT->disconnect();
      }
      return rv;
    }
  }

  assert(this->sendbuf_.left() >= this->max_pktlen_);
  
  int rv = pT->write_streams(); 
  if (rv != 0) {
    if (rv == NETWORK_ERR_SEND_BLOCKED) {
      pT->SetRTTimer();
    }
    return rv;
  }

  // if (should_exit_) {
  //   last_error_ = quic_err_app(0);
  //   pT->disconnect();
  //   return -1;
  // }

  SetRTTimer();
  return 0;
  }

};

/*!
 *	@brief QuicClientManagerT 定义.
 *
 *	封装QuicClientManagerT，实现Quick服务
 */
template <class T, class TSocket, class THandlerSet>
class QuicClientManagerT : public QuicManagerBaseT<T, TSocket, THandlerSet> {
  typedef QuicClientManagerT<T, TSocket, THandlerSet> This;
  typedef QuicManagerBaseT<T, TSocket, THandlerSet> Base;
 public:
  using typename Base::Buffer;
  typedef typename Base::Handler Handler;

 protected:
  SSL_CTX *create_client_ctx(const char *private_key_file,
                             const char *cert_file) {
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

    SSL_CTX_set_quic_method(ssl_ctx, &this->quic_method);

    if (this->session_file) {
      SSL_CTX_set_session_cache_mode(
          ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
      SSL_CTX_sess_set_new_cb(ssl_ctx,
                              // int new_session_cb
                              [](SSL *ssl, SSL_SESSION *session) {
                                auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
                                if (SSL_SESSION_get_max_early_data(session) !=  std::numeric_limits<uint32_t>::max()) {
                                  std::cerr << "max_early_data_size is not 0xffffffff " << std::endl;
                                }
                                auto f = BIO_new_file(h->get_manager()->session_file, "w");
                                if (f == nullptr) {
                                  std::cerr << "Could not write TLS session in " << h->get_manager()->session_file << std::endl;
                                  return 0;
                                }

                                PEM_write_bio_SSL_SESSION(f, session);
                                BIO_free(f);

                                return 0;
                              });
    }

    return ssl_ctx;
  }

 public:
  QuicClientManagerT(int max_handlerset_count) : Base(max_handlerset_count) {}

  bool Start(const char *private_key_file = nullptr,
             const char *cert_file = nullptr) {
    if (!Base::Start()) {
      return false;
    }
    this->ssl_ctx_ = create_client_ctx(private_key_file, cert_file);
    return true;
  }

  bool AddConnect(std::shared_ptr<TSocket> ep, const Address &remote_addr,
                  const std::string &host, u_short port) {
    T *pT = static_cast<T *>(this);
    auto handler_ptr = std::make_shared<Handler>(pT, ep, this->ssl_ctx_);
    if (!handler_ptr) {
      return false;
    }

    auto dcid = handler_ptr->rcid();
    auto dcid_key = make_cid_key(dcid);
    auto scid = handler_ptr->scid();
    auto scid_key = make_cid_key(scid);
    std::cerr << " dcid: " << format_hex(dcid_key) << " scid: " << format_hex(scid_key) << std::endl;
    this->ctos_.emplace(dcid_key, scid_key);
    this->handlers_.emplace(scid_key, handler_ptr);
    AddSocket(handler_ptr);
    handler_ptr->Post([ep, remote_addr, host, port, handler_ptr]() {
      handler_ptr->init(ep, remote_addr, host, port);
      handler_ptr->on_write();
    });
  }

  inline bool IsServer() { return false; }

  // work path
  const char *work_path;
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // disable_early_data disables early data.
  bool disable_early_data;

  void OnRecvBuf(std::shared_ptr<TSocket> ep, Buffer& buf)
	{
    T *pT = static_cast<T *>(this);
    if (packet_lost(this->rx_loss_prob)) {
      if (IsDebug()) {
        std::cerr << "** Simulated incoming packet loss **" << std::endl;
      }
      return;
    }

    char* lpBuf = buf.data();
		int nBufLen = buf.left();
		SOCKADDR* lpAddr = buf.addr();
		int nAddrLen = buf.addrlen();
    if (nBufLen == 0) {
      return;
    }

    uint32_t version;
    const uint8_t *dcid, *scid;
    size_t dcidlen, scidlen;
    auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen, &scid,
                                            &scidlen, (const uint8_t *)lpBuf,
                                            nBufLen, NGTCP2_SV_SCIDLEN);
    if (rv != 0) {
      std::cerr << "Could not decode version and CID from QUIC packet header: " << ngtcp2_strerror(rv) << std::endl;
      return;
    }

    auto dcid_key = make_cid_key(dcid, dcidlen);
    auto scid_key = make_cid_key(scid, scidlen);
    std::cerr << " dcid: " << format_hex(dcid_key) << " scid: " << format_hex(scid_key) << std::endl;
    auto handler_it = this->handlers_.find(dcid_key);
    if (handler_it == this->handlers_.end()) {
      auto ctos_it = this->ctos_.find(dcid_key);
      if (ctos_it == this->ctos_.end()) {
        return;
      }
      if (IsDebug()) {
        std::cerr << "Forward CID=" << format_hex((*ctos_it).first)
                  << " to CID=" << format_hex((*ctos_it).second) << std::endl;
      }
      handler_it = this->handlers_.find((*ctos_it).second);
      assert(handler_it != this->handlers_.end());
    }

    auto h = (*handler_it).second.get();
    /*struct Task
    {
      Task(Buffer&& b):buf_(std::move(b)){}
      Buffer buf_;
    };
    auto t = std::make_shared<Task>(std::move(buf));
    h->Post([t]() mutable -> void {
       auto b = std::move(t->buf_);
    });*/
    // auto str = std::make_unique<std::string>();
    // auto lambda = [capturedStr = std::move(str)]()mutable{
    //     std::cout << *capturedStr.get() << std::endl;
    // };
    // lambda();
    h->Post([h,ep,buf]()mutable{
        h->on_read(ep, buf.addr(), buf.addrlen(), (uint8_t *)buf.data(), buf.size());
        h->on_write();
    });
    // std::async(
    // //ThreadPool::Inst().Post(
    //   [](Buffer&& buf) {
    //   auto p = buf.data();
    // },std::move(buf));
    //h->on_read(ep, lpAddr, nAddrLen, (uint8_t *)lpBuf, nBufLen);
  }

};

}  // namespace XSocket

#endif  //_H_XQUICCLIENT_IMPL_H_
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
#ifndef _H_XQUICSERVER_IMPL_H_
#define _H_XQUICSERVER_IMPL_H_

#include "XQuicImpl.h"

namespace XSocket {

template <class T, class TManager, class TSocket, class TBase>
class QuicServerHandlerT
    : public QuicHandlerBaseT<T, TManager, TSocket, TBase> {
  typedef QuicServerHandlerT<T, TManager, TSocket, TBase> This;
  typedef QuicHandlerBaseT<T, TManager, TSocket, TBase> Base;
  using typename Base::Buffer;

 protected:
  ngtcp2_cid pscid_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  // draining_ becomes true when draining period starts.
  bool draining_;

 public:
  QuicServerHandlerT(TManager *manager, std::shared_ptr<TSocket> ep, SSL_CTX *ssl_ctx,
                     const ngtcp2_cid *rcid)
      : Base(manager, ep, ssl_ctx),
        pscid_{},
        draining_(false) {
          this->rcid_ = *rcid;
        }

  const ngtcp2_cid *pscid() const { return &pscid_; }

  bool draining() const { return draining_; }

  int init(const sockaddr *sa, socklen_t salen, const ngtcp2_cid *dcid,
           const ngtcp2_cid *scid, const ngtcp2_cid *ocid, const uint8_t *token,
           size_t tokenlen, uint32_t version) {
    this->remote_addr_.len = salen;
    memcpy(&this->remote_addr_.su.sa, sa, salen);

    switch (this->remote_addr_.su.storage.ss_family) {
      case AF_INET:
        this->max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
        break;
      case AF_INET6:
        this->max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
        break;
      default:
        return -1;
    }

    this->ssl_ = SSL_new(this->ssl_ctx_);
    SSL_set_app_data(this->ssl_, this);
    SSL_set_accept_state(this->ssl_);
    SSL_set_quic_early_data_enabled(this->ssl_, 1);

    auto callbacks = ngtcp2_conn_callbacks{
        nullptr,  // client_initial
        //::recv_client_initial,
        [](ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data) -> int {
          auto h = static_cast<T *>(user_data);

          if (h->recv_client_initial(dcid) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        //::recv_crypto_data,
        [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level, uint64_t offset,
           const uint8_t *data, size_t datalen, void *user_data) -> int {
          // if (!config.quiet && !config.no_quic_dump) {
          //   debug::print_crypto_data(crypto_level, data, datalen);
          // }

          auto h = static_cast<T *>(user_data);

          if (h->recv_crypto_data(crypto_level, data, datalen) != 0) {
            auto err = ngtcp2_conn_get_tls_error(conn);
            if (err) {
              return err;
            }
            return (int)NGTCP2_ERR_CRYPTO;
          }

          return 0;
        },
        //::handshake_completed,
        [](ngtcp2_conn *conn, void *user_data) {
          auto h = static_cast<T *>(user_data);

          // if (!config.quiet) {
          //   debug::handshake_completed(conn, user_data);
          // }

          if (h->handshake_completed() != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        nullptr,  // recv_version_negotiation
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        // do_hp_mask,
        [](uint8_t *dest, const ngtcp2_crypto_cipher *hp, const uint8_t *hp_key,
           const uint8_t *sample) {
          if (ngtcp2_crypto_hp_mask(dest, hp, hp_key, sample) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          // if (!config.quiet && config.show_secret) {
          //   debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample,
          //   NGTCP2_HP_SAMPLELEN);
          // }

          return 0;
        },
        //::recv_stream_data,
        [](ngtcp2_conn *conn, int64_t stream_id, int fin, uint64_t offset,
           const uint8_t *data, size_t datalen, void *user_data,
           void *stream_user_data) {
          auto h = static_cast<T *>(user_data);

          if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }

          return 0;
        },
        // acked_crypto_offset,
        [](ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level, uint64_t offset,
           size_t datalen, void *user_data) {
          auto h = static_cast<T *>(user_data);
          h->remove_tx_crypto_data(crypto_level, offset, datalen);
          return 0;
        },
        //::acked_stream_data_offset,
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t offset,
           size_t datalen, void *user_data, void *stream_user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->acked_stream_data_offset(stream_id, datalen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // stream_open,
        [](ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
          auto h = static_cast<T *>(user_data);
          h->on_stream_open(stream_id);
          return 0;
        },
        // stream_close,
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
           void *user_data, void *stream_user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->on_stream_close(stream_id, app_error_code) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        nullptr,  // recv_stateless_reset
        nullptr,  // recv_retry
        nullptr,  // extend_max_streams_bidi
        nullptr,  // extend_max_streams_uni
        // rand,
        [](ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
           ngtcp2_rand_ctx ctx, void *user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->rand(conn, dest, destlen, ctx) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // get_new_connection_id,
        [](ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
           void *user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->get_new_connection_id(conn, cid, token, cidlen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // remove_connection_id,
        [](ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->remove_connection_id(conn, cid) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        //::update_key
        [](ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
           uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
           const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
           size_t secretlen, void *user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->update_key(rx_secret, tx_secret, rx_key, rx_iv, tx_key, tx_iv,
                            current_rx_secret, current_tx_secret,
                            secretlen) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        // path_validation,
        [](ngtcp2_conn *conn, const ngtcp2_path *path,
           ngtcp2_path_validation_result res, void *user_data) {
          // if (!config.quiet) {
          //   debug::path_validation(path, res);
          // }
          return 0;
        },
        nullptr,  // select_preferred_addr
        //::stream_reset,
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
           uint64_t app_error_code, void *user_data, void *stream_user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->on_stream_reset(stream_id) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
        //::extend_max_remote_streams_bidi,
        [](ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
          auto h = static_cast<T *>(user_data);
          h->extend_max_remote_streams_bidi(max_streams);
          return 0;
        },
        nullptr,  // extend_max_remote_streams_uni,
        //::extend_max_stream_data,
        [](ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data,
           void *user_data, void *stream_user_data) {
          auto h = static_cast<T *>(user_data);
          if (h->extend_max_stream_data(stream_id, max_data) != 0) {
            return (int)NGTCP2_ERR_CALLBACK_FAILURE;
          }
          return 0;
        },
    };

    auto dis = std::uniform_int_distribution<>(0);

    this->scid_.datalen = NGTCP2_SV_SCIDLEN;
    std::generate(this->scid_.data, this->scid_.data + this->scid_.datalen,
                  [&dis]() { return dis(randgen) % 255; });

    ngtcp2_settings settings = {0};
    ngtcp2_settings_default(&settings);
    settings.log_printf = IsDebug() ? printf : nullptr;
    settings.initial_ts = timestamp();
    settings.token = ngtcp2_vec{const_cast<uint8_t *>(token), tokenlen};
    /*if (!config.qlog_dir.empty()) {
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
    }*/
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
    params.stateless_reset_token_present = 1;
    params.active_connection_id_limit = 7;

    if (ocid) {
      params.original_connection_id = *ocid;
      params.original_connection_id_present = 1;
    }

    std::generate(std::begin(params.stateless_reset_token),
                  std::end(params.stateless_reset_token),
                  [&dis]() { return dis(randgen); });

    if (this->manager_->preferred_ipv4_addr.len ||
        this->manager_->preferred_ipv6_addr.len) {
      params.preferred_address_present = 1;
      if (this->manager_->preferred_ipv4_addr.len) {
        auto &dest = params.preferred_address.ipv4_addr;
        const auto &addr = this->manager_->preferred_ipv4_addr;
        assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
        memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
        params.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
      }
      if (this->manager_->preferred_ipv6_addr.len) {
        auto &dest = params.preferred_address.ipv6_addr;
        const auto &addr = this->manager_->preferred_ipv6_addr;
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
        {this->sock_ptr_->local_addr_.len,
         const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&this->sock_ptr_->local_addr_.su)),
         this->sock_ptr_.get()},
        {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
    auto rv = ngtcp2_conn_server_new(&this->conn_, dcid, &this->scid_, &path, version,
                                     &callbacks, &settings, nullptr, this);
    if (rv != 0) {
      std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv)
                << std::endl;
      return -1;
    }

    std::array<uint8_t, 512> buf;

    auto nwrite = ngtcp2_encode_transport_params(
        buf.data(), buf.size(),
        NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
    if (nwrite < 0) {
      std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
                << std::endl;
      return -1;
    }

    if (SSL_set_quic_transport_params(this->ssl_, buf.data(), nwrite) != 1) {
      std::cerr << "SSL_set_quic_transport_params failed" << std::endl;
      return -1;
    }

    SetTimer(this->manager_->timeout / NGTCP2_MILLISECONDS);

    return 0;
  }

  void OnTimer() {
          auto s = this->manager_;

          if (ngtcp2_conn_is_in_closing_period(this->get_conn())) {
            if (IsDebug()) {
              std::cerr << "Closing Period is over" << std::endl;
            }

            s->remove(this);
            return;
          }
          if (draining()) {
            if (IsDebug()) {
              std::cerr << "Draining Period is over" << std::endl;
            }

            s->remove(this);
            return;
          }

          if (IsDebug()) {
            std::cerr << "Timeout" << std::endl;
          }

          this->start_draining_period();
        }

  void OnRTTimer() {
      int rv;

      auto s = this->manager_;

      if (IsDebug()) {
        std::cerr << "Timer expired" << std::endl;
      }

      rv = this->handle_expiry();
      if (rv != 0) {
        goto fail;
      }

      rv = this->on_write();
      if (rv != 0) {
        goto fail;
      }

      return;

    fail:
      switch (rv) {
        case NETWORK_ERR_CLOSE_WAIT:
          //ev_timer_stop(loop, w);
          return;
        default:
          s->remove(this);
          return;
      }
    }

int handle_expiry() {
  auto now = timestamp();
  if (ngtcp2_conn_loss_detection_expiry(this->conn_) <= now) {
    if (IsDebug()) {
      std::cerr << "Loss detection timer expired" << std::endl;
    }
  }

  if (ngtcp2_conn_ack_delay_expiry(this->conn_) <= now) {
    if (IsDebug()) {
      std::cerr << "Delayed ACK timer expired" << std::endl;
    }
  }

  auto rv = ngtcp2_conn_handle_expiry(this->conn_, now);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
              << std::endl;
    this->last_error_ = quic_err_transport(rv);
    return handle_error();
  }

  return 0;
}

  int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
                      const uint8_t *tx_secret, size_t secretlen) {
    std::array<uint8_t, 64> rx_key, rx_iv, rx_hp_key, tx_key, tx_iv, tx_hp_key;

    if (ngtcp2_crypto_derive_and_install_key(
            this->conn_, this->ssl_, rx_key.data(), rx_iv.data(), rx_hp_key.data(),
            tx_key.data(), tx_iv.data(), tx_hp_key.data(), level, rx_secret,
            tx_secret, secretlen, NGTCP2_CRYPTO_SIDE_SERVER) != 0) {
      return -1;
    }

    auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(this->conn_);
    auto aead = &crypto_ctx->aead;
    auto keylen = ngtcp2_crypto_aead_keylen(aead);
    auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

    const char *title = nullptr;
    switch (level) {
    case NGTCP2_CRYPTO_LEVEL_EARLY:
      title = "early_traffic";
      //keylog::log_secret(ssl_, keylog::QUIC_CLIENT_EARLY_TRAFFIC_SECRET,
      //                  rx_secret, secretlen);
      break;
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
      title = "handshake_traffic";
      //keylog::log_secret(ssl_, keylog::QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
      //                  rx_secret, secretlen);
      //keylog::log_secret(ssl_, keylog::QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET,
      //                  tx_secret, secretlen);
      break;
    case NGTCP2_CRYPTO_LEVEL_APP:
      title = "application_traffic";
      //keylog::log_secret(ssl_, keylog::QUIC_CLIENT_TRAFFIC_SECRET_0, rx_secret,
      //                  secretlen);
      //keylog::log_secret(ssl_, keylog::QUIC_SERVER_TRAFFIC_SECRET_0, tx_secret,
      //                  secretlen);
      break;
    default:
      assert(0);
    }

    // if (!config.quiet && config.show_secret) {
    //   std::cerr << title << " rx secret" << std::endl;
    //   debug::print_secrets(rx_secret, secretlen, rx_key.data(), keylen,
    //                       rx_iv.data(), ivlen, rx_hp_key.data(), keylen);
    //   if (tx_secret) {
    //     std::cerr << title << " tx secret" << std::endl;
    //     debug::print_secrets(tx_secret, secretlen, tx_key.data(), keylen,
    //                         tx_iv.data(), ivlen, tx_hp_key.data(), keylen);
    //   }
    // }

    // if (level == NGTCP2_CRYPTO_LEVEL_APP && setup_httpconn() != 0) {
    //   return -1;
    // }

    return 0;
  }

int update_key(uint8_t *rx_secret, uint8_t *tx_secret, uint8_t *rx_key,
                        uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
                        const uint8_t *current_rx_secret,
                        const uint8_t *current_tx_secret, size_t secretlen) {
  auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(this->conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

  ++this->nkey_update_;

  if (ngtcp2_crypto_update_key(this->conn_, rx_secret, tx_secret, rx_key, rx_iv,
                               tx_key, tx_iv, current_rx_secret,
                               current_tx_secret, secretlen) != 0) {
    return -1;
  }

  // if (!config.quiet && config.show_secret) {
  //   std::cerr << "application_traffic rx secret " << nkey_update_ << std::endl;
  //   debug::print_secrets(rx_secret, secretlen, rx_key, keylen, rx_iv, ivlen);
  //   std::cerr << "application_traffic tx secret " << nkey_update_ << std::endl;
  //   debug::print_secrets(tx_secret, secretlen, tx_key, keylen, tx_iv, ivlen);
  // }

  return 0;
}

  int recv_client_initial(const ngtcp2_cid *dcid) {
    std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN> initial_secret,
        rx_secret, tx_secret;
    std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN> rx_key, rx_hp_key, tx_key,
        tx_hp_key;
    std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN> rx_iv, tx_iv;

    if (ngtcp2_crypto_derive_and_install_initial_key(
            this->conn_, rx_secret.data(), tx_secret.data(),
            initial_secret.data(), rx_key.data(), rx_iv.data(),
            rx_hp_key.data(), tx_key.data(), tx_iv.data(), tx_hp_key.data(),
            dcid, NGTCP2_CRYPTO_SIDE_SERVER) != 0) {
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

  void start_draining_period() {
    draining_ = true;

    auto millis = ngtcp2_conn_get_pto(this->conn_) / NGTCP2_MILLISECONDS * 3;
    SetTimer(millis);

    if (IsDebug()) {
      std::cerr << "Draining period has started (" << millis / NGTCP2_SECONDS
                << " seconds)" << std::endl;
    }
  }

  int start_closing_period() {
    if (!this->conn_ || ngtcp2_conn_is_in_closing_period(this->conn_)) {
      return 0;
    }

    auto millis = ngtcp2_conn_get_pto(this->conn_) / NGTCP2_MILLISECONDS * 3;
    SetTimer(millis);

    if (IsDebug()) {
      std::cerr << "Closing period has started (" << millis / NGTCP2_SECONDS
                << " seconds)" << std::endl;
    }

    this->sendbuf_.reset();
    assert(this->sendbuf_.left() >= this->max_pktlen_);

    conn_closebuf_ =
        std::unique_ptr<Buffer>(new Buffer(NGTCP2_MAX_PKTLEN_IPV4));

    PathStorage path;
    if (this->last_error_.type == QUICErrorType::Transport) {
      auto n = ngtcp2_conn_write_connection_close(
          this->conn_, &path.path, conn_closebuf_->wpos(), this->max_pktlen_,
          this->last_error_.code, timestamp());
      if (n < 0) {
        std::cerr << "ngtcp2_conn_write_connection_close: "
                  << ngtcp2_strerror(n) << std::endl;
        return -1;
      }
      conn_closebuf_->push(n);
    } else {
      auto n = ngtcp2_conn_write_application_close(
          this->conn_, &path.path, conn_closebuf_->wpos(), this->max_pktlen_,
          this->last_error_.code, timestamp());
      if (n < 0) {
        std::cerr << "ngtcp2_conn_write_application_close: "
                  << ngtcp2_strerror(n) << std::endl;
        return -1;
      }
      conn_closebuf_->push(n);
    }

    //update_endpoint(&path.path.local);
    update_remote_addr(&path.path.remote);

    return 0;
  }

  int handle_error() {
    if (start_closing_period() != 0) {
      return -1;
    }

    auto rv = send_conn_close();
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }

    return NETWORK_ERR_CLOSE_WAIT;
  }

  int send_conn_close() {
    if (IsDebug()) {
      std::cerr << "Closing Period: TX CONNECTION_CLOSE" << std::endl;
    }

    assert(conn_closebuf_ && conn_closebuf_->size());

    if (this->sendbuf_.size() == 0) {
      std::copy_n(conn_closebuf_->rpos(), conn_closebuf_->size(),
                  this->sendbuf_.wpos());
      this->sendbuf_.push(conn_closebuf_->size());
    }

    return this->manager_->send_packet(this->sock_ptr_, this->sendbuf_.rpos(), this->sendbuf_.size()
    , &this->remote_addr_.su.sa, this->remote_addr_.len, 0);
    return 0;
  }

int on_write() {
    T* pT = static_cast<T*>(this);
  if (ngtcp2_conn_is_in_closing_period(this->conn_) ||
      ngtcp2_conn_is_in_draining_period(this->conn_)) {
    return 0;
  }

  if (auto rv = pT->write_streams(); rv != 0) {
    return rv;
  }

  pT->SetRTTimer();

  return 0;
}

};

/*!
 *	@brief QuicServerManagerT 定义.
 *
 *	封装QuicServerManagerT，实现Quick服务
 */
template <class T, class TSocket, class THandlerSet>
class QuicServerManagerT : public QuicManagerBaseT<T, TSocket, THandlerSet> {
  typedef QuicServerManagerT<T, TSocket, THandlerSet> This;
  typedef QuicManagerBaseT<T, TSocket, THandlerSet> Base;

 public:
  using typename Base::Buffer;
  typedef typename Base::Handler Handler;

 protected:
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;

  SSL_CTX *create_server_ctx(const char *private_key_file,
                             const char *cert_file) {
    constexpr static char sid_ctx[] = "ngtcp2 server";

    auto ssl_ctx = SSL_CTX_new(TLS_server_method());

    constexpr auto ssl_opts =
        (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
        SSL_OP_SINGLE_ECDH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_NO_ANTI_REPLAY;

    SSL_CTX_set_options(ssl_ctx, ssl_opts);

    if (SSL_CTX_set_ciphersuites(ssl_ctx, this->ciphers) != 1) {
      std::cerr << "SSL_CTX_set_ciphersuites: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      exit(EXIT_FAILURE);
    }

    if (SSL_CTX_set1_groups_list(ssl_ctx, this->groups) != 1) {
      std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
      exit(EXIT_FAILURE);
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    SSL_CTX_set_alpn_select_cb(ssl_ctx, 
    //int alpn_select_proto_cb
    [](SSL *ssl, const unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg) {
    auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
    const uint8_t *alpn;
    size_t alpnlen;
    auto version = ngtcp2_conn_get_negotiated_version(h->get_conn());

    switch (version) {
      case NGTCP2_PROTO_VER:
        alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_H3);
        alpnlen = str_size(NGTCP2_ALPN_H3);
        break;
      default:
        if (h->IsDebug()) {
          std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
                    << version << std::dec << std::endl;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
      if (std::equal(alpn, alpn + alpnlen, p)) {
        *out = p + 1;
        *outlen = *p;
        return SSL_TLSEXT_ERR_OK;
      }
    }

    if (h->IsDebug()) {
      std::cerr << "Client did not present ALPN " << &NGTCP2_ALPN_H3[1]
                << std::endl;
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }, 
  nullptr);

    SSL_CTX_set_default_verify_paths(ssl_ctx);

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

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
      std::cerr << "SSL_CTX_check_private_key: "
                << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
      exit(EXIT_FAILURE);
    }

    SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);

    if (this->verify_client) {
      SSL_CTX_set_verify(ssl_ctx,
                         SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                             SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         // int verify_cb
                         [](int preverify_ok, X509_STORE_CTX *ctx) {
                           // We don't verify the client certificate.  Just
                           // request it for the testing purpose.
                           return 1;
                         });
    }

    SSL_CTX_set_max_early_data(ssl_ctx, std::numeric_limits<uint32_t>::max());
    SSL_CTX_set_quic_method(ssl_ctx, &this->quic_method);
    SSL_CTX_set_client_hello_cb(
        ssl_ctx,
        // int client_hello_cb
        [](SSL *ssl, int *al, void *arg) {
          const uint8_t *tp;
          size_t tplen;

          if (!SSL_client_hello_get0_ext(
                  ssl, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS, &tp, &tplen)) {
            *al = SSL_AD_INTERNAL_ERROR;
            return SSL_CLIENT_HELLO_ERROR;
          }

          return SSL_CLIENT_HELLO_SUCCESS;
        },
        nullptr);

    return ssl_ctx;
  }
 public:
  QuicServerManagerT(int max_handlerset_count)
      : Base(max_handlerset_count) {
    
  }

  ~QuicServerManagerT() {}

	bool Start(const char *private_key_file, const char *cert_file)
	{
    if(!Base::Start()) {
      return false;
    }
    this->ssl_ctx_ = create_server_ctx(private_key_file, cert_file);
    return true;
  }

  Address preferred_ipv4_addr;
  Address preferred_ipv6_addr;
  // server name
  std::string server_;
  // port is the port number which server listens on for incoming
  // connections.
  uint16_t port_;
  // validate_addr is true if server requires address validation.
  bool validate_addr;
  // verify_client is true if server verifies client with X.509
  // certificate based authentication.
  bool verify_client;

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

  static inline void generate_rand_data(uint8_t *buf, size_t len) {
    auto dis = std::uniform_int_distribution<>(0);
    std::generate_n(buf, len, [&dis]() { return dis(randgen) % 255; });
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

    if (ngtcp2_crypto_derive_packet_protection_key(
            key, iv, nullptr, &token_aead_, &token_md_, secret.data(),
            secret.size()) != 0) {
      return -1;
    }

    return 0;
  }

  inline int generate_token(uint8_t *token, size_t &tokenlen,
                            const sockaddr *sa, socklen_t salen,
                            const ngtcp2_cid *ocid) {
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
    if (ngtcp2_crypto_encrypt(token, &token_aead_, plaintext.data(),
                              plaintextlen, key.data(), iv.data(), ivlen,
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
    if (rv != 0) {
      std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
      return -1;
    }

    if (IsDebug()) {
      std::cerr << "Verifying token from [" << host.data()
                << "]:" << port.data() << std::endl;
    }

    if (IsDebug()) {
      std::cerr << "Received address validation token:" << std::endl;
      // util::hexdump(stderr, hd->token, hd->tokenlen);
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

  int send_version_negotiation(std::shared_ptr<TSocket> ep, uint32_t version,
                               const uint8_t *dcid, size_t dcidlen,
                               const uint8_t *scid, size_t scidlen,
                               const sockaddr *sa, socklen_t salen) {
    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
    uint32_t sv[2] = {0};

    sv[0] = generate_reserved_version(sa, salen, version);
    sv[1] = NGTCP2_PROTO_VER;

    auto nwrite = ngtcp2_pkt_write_version_negotiation(
        buf, sizeof(buf), std::uniform_int_distribution<>(0)(randgen) % 255,
        dcid, dcidlen, scid, scidlen, sv, 2);
    if (nwrite < 0) {
      std::cerr << "ngtcp2_pkt_write_version_negotiation: "
                << ngtcp2_strerror(nwrite) << std::endl;
      return -1;
    }

    send_packet(ep, (const char *)buf, nwrite, sa, salen);

    return 0;
  }

  int send_retry(std::shared_ptr<TSocket> ep, const ngtcp2_pkt_hd *chd, const sockaddr *sa,
                 socklen_t salen) {
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
      // util::hexdump(stderr, token.data(), tokenlen);
    }

    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
    ngtcp2_cid scid;

    scid.datalen = NGTCP2_SV_SCIDLEN;
    auto dis = std::uniform_int_distribution<>(0);
    std::generate(scid.data, scid.data + scid.datalen,
                  [&dis]() { return dis(randgen) % 255; });

    auto nwrite = ngtcp2_crypto_write_retry(buf, sizeof(buf), &chd->scid, &scid,
                                            &chd->dcid, token.data(), tokenlen);
    if (nwrite < 0) {
      std::cerr << "ngtcp2_crypto_write_retry failed" << std::endl;
      return -1;
    }

    send_packet(ep, (const char *)buf, nwrite, sa, salen);

    return 0;
  }

  int send_stateless_connection_close(std::shared_ptr<TSocket> ep, const ngtcp2_pkt_hd *chd,
                                      const sockaddr *sa, socklen_t salen) {
    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};

    auto nwrite = ngtcp2_crypto_write_connection_close(
        buf, sizeof(buf), &chd->scid, &chd->dcid, NGTCP2_INVALID_TOKEN);
    if (nwrite < 0) {
      std::cerr << "ngtcp2_crypto_write_connection_close failed" << std::endl;
      return -1;
    }

    send_packet(ep, (const char *)buf, nwrite, sa, salen);

    return 0;
  }

  void remove(const Handler *h) {
    this->ctos_.erase(make_cid_key(h->pscid()));
    Base::remove(h);
  }

 public:
  //
  //解析数据包
  //virtual int OnRecvBuf(std::shared_ptr<TSocket> ep, const char *buf, int &nread,
  //                      const SOCKADDR *sa, int salen) {
  void OnRecvBuf(std::shared_ptr<TSocket> ep, Buffer& b)
	{
    T *pT = static_cast<T *>(this);
    const char *buf = b.data();
    int nread = b.size();
    const SOCKADDR *sa = b.addr(); 
    int salen = b.addrlen();
    // 		sockaddr_union su;
    //   socklen_t addrlen;
    //   std::array<uint8_t, 64_k> buf;
    ngtcp2_pkt_hd hd;
    //   size_t pktcnt = 0;

    //   for (; pktcnt < 10;) {
    //     addrlen = sizeof(su);
    //     auto nread =
    //         recvfrom(ep.fd, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa,
    //         &addrlen);
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
    //                 << " remote=" << util::straddr(&su.sa, addrlen) << " " <<
    //                 nread
    //                 << " bytes" << std::endl;
    //     }

    if (packet_lost(this->rx_loss_prob)) {
      if (IsDebug()) {
        std::cerr << "** Simulated incoming packet loss **" << std::endl;
      }
      return;
    }

    if (nread == 0) {
      return;
    }

    uint32_t version;
    const uint8_t *dcid, *scid;
    size_t dcidlen, scidlen;
    auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen, &scid,
                                            &scidlen, (const uint8_t *)buf,
                                            nread, NGTCP2_SV_SCIDLEN);
    if (rv != 0) {
      if (rv == 1) {
        send_version_negotiation(ep, version, scid, scidlen, dcid, dcidlen, sa, salen);
        return;
      }
      std::cerr << "Could not decode version and CID from QUIC packet header: "
                << ngtcp2_strerror(rv) << std::endl;
      return;
    }

    
    auto dcid_key = make_cid_key(dcid, dcidlen);
    auto scid_key = make_cid_key(scid, scidlen);
    std::cerr << " dcid: " << format_hex(dcid_key) << " scid: " << format_hex(scid_key) << std::endl;
    auto handler_it = this->handlers_.find(dcid_key);
    if (handler_it == this->handlers_.end()) {
      auto ctos_it = this->ctos_.find(dcid_key);
      if (ctos_it == this->ctos_.end()) {
        rv = ngtcp2_accept(&hd, (const uint8_t *)buf, nread);
        if (rv == -1) {
          if (IsDebug()) {
            std::cerr << "Unexpected packet received: length=" << nread
                      << std::endl;
          }
          return;
        } else if (rv == 1) {
          if (IsDebug()) {
            std::cerr << "Unsupported version: Send Version Negotiation"
                      << std::endl;
          }
          send_version_negotiation(ep, hd.version, hd.scid.data,
                                   hd.scid.datalen, hd.dcid.data,
                                   hd.dcid.datalen, sa, salen);
          return;
        }

        ngtcp2_cid ocid;
        ngtcp2_cid *pocid = nullptr;
        switch (hd.type) {
          case NGTCP2_PKT_INITIAL:
            if (validate_addr || hd.tokenlen) {
              std::cerr << "Perform stateless address validation" << std::endl;
              if (hd.tokenlen == 0) {
                send_retry(ep, &hd, sa, salen);
                return;
              }
              if (verify_token(&ocid, &hd, sa, salen) != 0) {
                send_stateless_connection_close(ep, &hd, sa, salen);
                return;
              }
              pocid = &ocid;
            }
            break;
          case NGTCP2_PKT_0RTT:
            send_retry(ep, &hd, sa, salen);
            return;
        }

        auto h = std::make_shared<Handler>(pT, ep, this->ssl_ctx_, &hd.dcid);
        if (h->init(sa, salen, &hd.scid, &hd.dcid, pocid, hd.token, hd.tokenlen,
                    hd.version) != 0) {
          return;
        }
        AddSocket(h);
        h->Post([this,hd,h,ep,buf = b](){
        switch (h->on_read(ep, buf.addr(), buf.addrlen(), (uint8_t *)buf.data(), buf.size())) {
          case 0:
            break;
          case NETWORK_ERR_RETRY:
            send_retry(ep, &hd, buf.addr(), buf.addrlen());
            return;
          default:
            return;
        }

        switch (h->on_write()) {
          case 0:
            break;
          default:
            return;
        }
        });
        auto scid = h->scid();
        auto scid_key = make_cid_key(scid);
        this->ctos_.emplace(dcid_key, scid_key);

        auto pscid = h->pscid();
        if (pscid->datalen) {
          auto pscid_key = make_cid_key(pscid);
          this->ctos_.emplace(pscid_key, scid_key);
        }

        this->handlers_.emplace(scid_key, h);
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
    h->Post([this,h,ep,buf = b](){
        if (ngtcp2_conn_is_in_closing_period(h->get_conn())) {
          // TODO do exponential backoff.
          switch (h->send_conn_close()) {
            case 0:
              break;
            default:
              remove(h);
          }
          return;
        }
        if (h->draining()) {
          return;
        }

        auto rv = h->on_read(ep, buf.addr(), buf.addrlen(), (uint8_t *)buf.data(), buf.size());
        if (rv != 0) {
          if (rv != NETWORK_ERR_CLOSE_WAIT) {
            remove(h);
          }
          return;
        }

        h->on_write();
    });

    //   }
  }
};

}  // namespace XSocket

#endif  //_H_XQUICSERVER_IMPL_H_
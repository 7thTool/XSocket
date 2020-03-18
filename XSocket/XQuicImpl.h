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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>
#include <string_view>
#include <sstream>
#include <strstream>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

namespace XSocket {

template<class TSocket, class TSockAddr>
class QuickHandler {
protected:
	
static void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  ev_io_stop(loop, w);

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  switch (h->on_write()) {
  case 0:
  case NETWORK_ERR_CLOSE_WAIT:
  case NETWORK_ERR_SEND_BLOCKED:
    return;
  default:
    s->remove(h);
  }
}

static 
void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  if (ngtcp2_conn_is_in_closing_period(h->conn())) {
    if (!config.quiet) {
      std::cerr << "Closing Period is over" << std::endl;
    }

    s->remove(h);
    return;
  }
  if (h->draining()) {
    if (!config.quiet) {
      std::cerr << "Draining Period is over" << std::endl;
    }

    s->remove(h);
    return;
  }

  if (!config.quiet) {
    std::cerr << "Timeout" << std::endl;
  }

  h->start_draining_period();
}
static 
void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;

  auto h = static_cast<Handler *>(w->data);
  auto s = h->server();

  if (!config.quiet) {
    std::cerr << "Timer expired" << std::endl;
  }

  rv = h->handle_expiry();
  if (rv != 0) {
    goto fail;
  }

  rv = h->on_write();
  if (rv != 0) {
    goto fail;
  }

  return;

fail:
  switch (rv) {
  case NETWORK_ERR_CLOSE_WAIT:
  case NETWORK_ERR_SEND_BLOCKED:
    ev_timer_stop(loop, w);
    return;
  default:
    s->remove(h);
    return;
  }
}

public:
QuickHandler(struct ev_loop *loop, SSL_CTX *ssl_ctx, Server *server,
                 const ngtcp2_cid *rcid)
    : endpoint_{nullptr},
      remote_addr_{},
      max_pktlen_(0),
      loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      server_(server),
      qlog_(nullptr),
      crypto_{},
      conn_(nullptr),
      scid_{},
      pscid_{},
      rcid_(*rcid),
      httpconn_{nullptr},
      sendbuf_{NGTCP2_MAX_PKTLEN_IPV4},
      last_error_{QUICErrorType::Transport, 0},
      nkey_update_(0),
      draining_(false) {
  ev_io_init(&wev_, writecb, 0, EV_WRITE);
  wev_.data = this;
  ev_timer_init(&timer_, timeoutcb, 0.,
                static_cast<double>(config.timeout) / NGTCP2_SECONDS);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
}

~QuickHandler() {
  if (!config.quiet) {
    std::cerr << "Closing QUIC connection" << std::endl;
  }

  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);
  ev_io_stop(loop_, &wev_);

  if (httpconn_) {
    nghttp3_conn_del(httpconn_);
  }

  if (conn_) {
    ngtcp2_conn_del(conn_);
  }

  if (ssl_) {
    SSL_free(ssl_);
  }

  if (qlog_) {
    fclose(qlog_);
  }
}

static
int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                        void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_client_initial(dcid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (!config.quiet) {
    debug::handshake_completed(conn, user_data);
  }

  if (h->handshake_completed() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int handshake_completed() {
  if (!config.quiet) {
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

static
int do_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
               const uint8_t *hp_key, const uint8_t *sample) {
  if (ngtcp2_crypto_hp_mask(dest, hp, hp_key, sample) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);
  }

  return 0;
}

static
int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_crypto_data(crypto_level, data, datalen);
  }

  auto h = static_cast<Handler *>(user_data);

  if (h->recv_crypto_data(crypto_level, data, datalen) != 0) {
    if (auto err = ngtcp2_conn_get_tls_error(conn); err) {
      return err;
    }
    return NGTCP2_ERR_CRYPTO;
  }

  return 0;
}

static
int recv_stream_data(ngtcp2_conn *conn, int64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);

  if (h->recv_stream_data(stream_id, fin, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static
int acked_crypto_offset(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                        uint64_t offset, size_t datalen, void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->remove_tx_crypto_data(crypto_level, offset, datalen);
  return 0;
}

static
int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->acked_stream_data_offset(stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int acked_stream_data_offset(int64_t stream_id, size_t datalen) {
  if (!httpconn_) {
    return 0;
  }

  if (auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
      rv != 0) {
    std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

static
int stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->on_stream_open(stream_id);
  return 0;
}
} // namespace

void on_stream_open(int64_t stream_id) {
  if (!ngtcp2_is_bidi_stream(stream_id)) {
    return;
  }
  auto it = streams_.find(stream_id);
  assert(it == std::end(streams_));
  streams_.emplace(stream_id, std::make_unique<Stream>(stream_id, this));
}

int push_content(int64_t stream_id, const std::string_view &authority,
                          const std::string_view &path) {
  auto nva = std::array<nghttp3_nv, 4>{
      util::make_nv(":method", "GET"),
      util::make_nv(":scheme", "https"),
      util::make_nv(":authority", authority),
      util::make_nv(":path", path),
  };

  int64_t push_id;
  if (auto rv = nghttp3_conn_submit_push_promise(httpconn_, &push_id, stream_id,
                                                 nva.data(), nva.size());
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_push_promise: " << nghttp3_strerror(rv)
              << std::endl;
    if (rv != NGHTTP3_ERR_PUSH_ID_BLOCKED) {
      return -1;
    }
    return 0;
  }

  if (!config.quiet) {
    debug::print_http_push_promise(stream_id, push_id, nva.data(), nva.size());
  }

  int64_t push_stream_id;
  if (auto rv = ngtcp2_conn_open_uni_stream(conn_, &push_stream_id, nullptr);
      rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    if (rv != NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return -1;
    }
    return 0;
  }

  if (!config.quiet) {
    debug::push_stream(push_id, push_stream_id);
  }

  Stream *stream;
  {
    auto p = std::make_unique<Stream>(push_stream_id, this);
    stream = p.get();
    streams_.emplace(push_stream_id, std::move(p));
  }

  if (auto rv =
          nghttp3_conn_bind_push_stream(httpconn_, push_id, push_stream_id);
      rv != 0) {
    std::cerr << "nghttp3_conn_bind_push_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  stream->uri = path;
  stream->method = "GET";
  stream->authority = authority;

  nghttp3_conn_set_stream_user_data(httpconn_, push_stream_id, stream);

  stream->start_response(httpconn_);

  return 0;
}

static
int stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->on_stream_close(stream_id, app_error_code) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static
int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->on_stream_reset(stream_id) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int Handler::on_stream_reset(int64_t stream_id) {
  if (httpconn_) {
    if (auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id); rv != 0) {
      std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

static
int rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx,
         void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
}

static
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  auto f = [&dis]() { return dis(randgen); };

  std::generate_n(cid->data, cidlen, f);
  cid->datalen = cidlen;
  auto md = ngtcp2_crypto_md{const_cast<EVP_MD *>(EVP_sha256())};
  if (ngtcp2_crypto_generate_stateless_reset_token(
          token, &md, config.static_secret.data(), config.static_secret.size(),
          cid) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  auto h = static_cast<Handler *>(user_data);
  h->server()->associate_cid(cid, h);

  return 0;
}

static
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->server()->dissociate_cid(cid);
  return 0;
}

static
int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               uint8_t *rx_key, uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->update_key(rx_secret, tx_secret, rx_key, rx_iv, tx_key, tx_iv,
                    current_rx_secret, current_tx_secret, secretlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static
int path_validation(ngtcp2_conn *conn, const ngtcp2_path *path,
                    ngtcp2_path_validation_result res, void *user_data) {
  if (!config.quiet) {
    debug::path_validation(path, res);
  }
  return 0;
}

static
int extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                   void *user_data) {
  auto h = static_cast<Handler *>(user_data);
  h->extend_max_remote_streams_bidi(max_streams);
  return 0;
}

void Handler::extend_max_remote_streams_bidi(uint64_t max_streams) {
  if (!httpconn_) {
    return;
  }

  nghttp3_conn_set_max_client_streams_bidi(httpconn_, max_streams);
}

static
int extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data) {
  auto h = static_cast<Handler *>(user_data);
  if (h->extend_max_stream_data(stream_id, max_data) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  if (auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

static
void write_qlog(void *user_data, const void *data, size_t datalen) {
  auto h = static_cast<Handler *>(user_data);
  h->write_qlog(data, datalen);
}

void write_qlog(const void *data, size_t datalen) {
  assert(qlog_);
  fwrite(data, 1, datalen, qlog_);
}

int init(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                  const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                  const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
                  uint32_t version) {
  endpoint_ = const_cast<Endpoint *>(&ep);

  remote_addr_.len = salen;
  memcpy(&remote_addr_.su.sa, sa, salen);

  switch (remote_addr_.su.storage.ss_family) {
  case AF_INET:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    return -1;
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_app_data(ssl_, this);
  SSL_set_accept_state(ssl_);
  SSL_set_quic_early_data_enabled(ssl_, 1);

  auto callbacks = ngtcp2_conn_callbacks{
      nullptr, // client_initial
      ::recv_client_initial,
      ::recv_crypto_data,
      ::handshake_completed,
      nullptr, // recv_version_negotiation
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      do_hp_mask,
      ::recv_stream_data,
      acked_crypto_offset,
      ::acked_stream_data_offset,
      stream_open,
      stream_close,
      nullptr, // recv_stateless_reset
      nullptr, // recv_retry
      nullptr, // extend_max_streams_bidi
      nullptr, // extend_max_streams_uni
      rand,
      get_new_connection_id,
      remove_connection_id,
      ::update_key,
      path_validation,
      nullptr, // select_preferred_addr
      ::stream_reset,
      ::extend_max_remote_streams_bidi,
      nullptr, // extend_max_remote_streams_uni,
      ::extend_max_stream_data,
  };

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);

  scid_.datalen = NGTCP2_SV_SCIDLEN;
  std::generate(scid_.data, scid_.data + scid_.datalen,
                [&dis]() { return dis(randgen); });

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.log_printf = config.quiet ? nullptr : debug::log_printf;
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
  ev_timer_again(loop_, &timer_);

  return 0;
}

void write_server_handshake(ngtcp2_crypto_level level,
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

int recv_client_initial(const ngtcp2_cid *dcid) {
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_SECRETLEN> initial_secret,
      rx_secret, tx_secret;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_KEYLEN> rx_key, rx_hp_key, tx_key,
      tx_hp_key;
  std::array<uint8_t, NGTCP2_CRYPTO_INITIAL_IVLEN> rx_iv, tx_iv;

  if (ngtcp2_crypto_derive_and_install_initial_key(
          conn_, rx_secret.data(), tx_secret.data(), initial_secret.data(),
          rx_key.data(), rx_iv.data(), rx_hp_key.data(), tx_key.data(),
          tx_iv.data(), tx_hp_key.data(), dcid,
          NGTCP2_CRYPTO_SIDE_SERVER) != 0) {
    std::cerr << "ngtcp2_crypto_derive_and_install_initial_key() failed"
              << std::endl;
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_initial_secret(initial_secret.data(), initial_secret.size());

    std::cerr << "initial rx secret" << std::endl;
    debug::print_secrets(rx_secret.data(), rx_secret.size(), rx_key.data(),
                         rx_key.size(), rx_iv.data(), rx_iv.size(),
                         rx_hp_key.data(), rx_hp_key.size());
    std::cerr << "initial tx secret" << std::endl;
    debug::print_secrets(tx_secret.data(), tx_secret.size(), tx_key.data(),
                         tx_key.size(), tx_iv.data(), tx_iv.size(),
                         tx_hp_key.data(), tx_hp_key.size());
  }

  return 0;
}

void update_endpoint(const ngtcp2_addr *addr) {
  endpoint_ = static_cast<Endpoint *>(addr->user_data);
  assert(endpoint_);
}

void update_remote_addr(const ngtcp2_addr *addr) {
  remote_addr_.len = addr->addrlen;
  memcpy(&remote_addr_.su, addr->addr, addr->addrlen);
}

int feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                       uint8_t *data, size_t datalen) {
  auto path = ngtcp2_path{
      {ep.addr.len,
       const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&ep.addr.su)),
       const_cast<Endpoint *>(&ep)},
      {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};

  if (auto rv = ngtcp2_conn_read_pkt(conn_, &path, data, datalen,
                                     util::timestamp(loop_));
      rv != 0) {
    std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
    switch (rv) {
    case NGTCP2_ERR_DRAINING:
      start_draining_period();
      return NETWORK_ERR_CLOSE_WAIT;
    case NGTCP2_ERR_RETRY:
      return NETWORK_ERR_RETRY;
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
    return handle_error();
  }

  return 0;
}

int on_read(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                     uint8_t *data, size_t datalen) {
  if (auto rv = feed_data(ep, sa, salen, data, datalen); rv != 0) {
    return rv;
  }

  reset_idle_timer();

  return 0;
}

void reset_idle_timer() {
  auto now = util::timestamp(loop_);
  auto idle_expiry = ngtcp2_conn_get_idle_expiry(conn_);
  timer_.repeat =
      idle_expiry > now
          ? static_cast<ev_tstamp>(idle_expiry - now) / NGTCP2_SECONDS
          : 1e-9;

  if (!config.quiet) {
    std::cerr << "Set idle timer=" << std::fixed << timer_.repeat << "s"
              << std::defaultfloat << std::endl;
  }

  ev_timer_again(loop_, &timer_);
}

int handle_expiry() {
  auto now = util::timestamp(loop_);
  if (ngtcp2_conn_loss_detection_expiry(conn_) <= now) {
    if (!config.quiet) {
      std::cerr << "Loss detection timer expired" << std::endl;
    }
  }

  if (ngtcp2_conn_ack_delay_expiry(conn_) <= now) {
    if (!config.quiet) {
      std::cerr << "Delayed ACK timer expired" << std::endl;
    }
  }

  if (auto rv = ngtcp2_conn_handle_expiry(conn_, now); rv != 0) {
    std::cerr << "ngtcp2_conn_handle_expiry: " << ngtcp2_strerror(rv)
              << std::endl;
    last_error_ = quic_err_transport(rv);
    return handle_error();
  }

  return 0;
}

int on_write() {
  if (ngtcp2_conn_is_in_closing_period(conn_) ||
      ngtcp2_conn_is_in_draining_period(conn_)) {
    return 0;
  }

  if (auto rv = write_streams(); rv != 0) {
    if (rv == NETWORK_ERR_SEND_BLOCKED) {
      schedule_retransmit();
    }
    return rv;
  }

  schedule_retransmit();

  return 0;
}

int write_streams() {
  std::array<nghttp3_vec, 16> vec;
  PathStorage path;
  size_t pktcnt = 0;
  constexpr size_t max_pktcnt = 10;
  std::array<uint8_t, std::max(NGTCP2_MAX_PKTLEN_IPV4, NGTCP2_MAX_PKTLEN_IPV6) *
                          max_pktcnt>
      buf;
  uint8_t *bufpos = buf.data();

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
        conn_, &path.path, bufpos, max_pktlen_, &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, util::timestamp(loop_));
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED &&
            ngtcp2_conn_get_max_data_left(conn_) == 0) {
          if (bufpos - buf.data()) {
            server_->send_packet(*endpoint_, remote_addr_, buf.data(),
                                 bufpos - buf.data(), max_pktlen_, &wev_);
            reset_idle_timer();
          }
          return 0;
        }

        if (auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);
            rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          return handle_error();
        }
        continue;
      case NGTCP2_ERR_WRITE_STREAM_MORE:
        assert(ndatalen > 0);
        if (auto rv =
                nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
            rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          return handle_error();
        }
        continue;
      }

      std::cerr << "ngtcp2_conn_writev_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      last_error_ = quic_err_transport(nwrite);
      return handle_error();
    }

    if (nwrite == 0) {
      if (bufpos - buf.data()) {
        server_->send_packet(*endpoint_, remote_addr_, buf.data(),
                             bufpos - buf.data(), max_pktlen_, &wev_);
        reset_idle_timer();
      }
      // We are congestion limited.
      return 0;
    }

    bufpos += nwrite;

    if (ndatalen >= 0) {
      if (auto rv =
              nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
          rv != 0) {
        std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                  << std::endl;
        last_error_ = quic_err_app(rv);
        return handle_error();
      }
    }

#if NGTCP2_ENABLE_UDP_GSO
    if (pktcnt == 0) {
      update_endpoint(&path.path.local);
      update_remote_addr(&path.path.remote);
    } else if (remote_addr_.len != path.path.remote.addrlen ||
               0 != memcmp(&remote_addr_.su, path.path.remote.addr,
                           path.path.remote.addrlen)) {
      server_->send_packet(*endpoint_, remote_addr_, buf.data(),
                           bufpos - buf.data() - nwrite, max_pktlen_, &wev_);

      update_remote_addr(&path.path.remote);

      server_->send_packet(*endpoint_, remote_addr_, bufpos - nwrite, nwrite,
                           max_pktlen_, &wev_);
      reset_idle_timer();
      ev_io_start(loop_, &wev_);
      return 0;
    }

    if (++pktcnt == max_pktcnt || static_cast<size_t>(nwrite) < max_pktlen_) {
      server_->send_packet(*endpoint_, remote_addr_, buf.data(),
                           bufpos - buf.data(), max_pktlen_, &wev_);
      reset_idle_timer();
      ev_io_start(loop_, &wev_);
      return 0;
    }
#else  // !NGTCP2_ENABLE_UDP_GSO
    update_endpoint(&path.path.local);
    update_remote_addr(&path.path.remote);
    reset_idle_timer();

    server_->send_packet(*endpoint_, remote_addr_, buf.data(),
                         bufpos - buf.data(), 0, &wev_);
    if (++pktcnt == max_pktcnt) {
      ev_io_start(loop_, &wev_);
      return 0;
    }

    bufpos = buf.data();
#endif // !NGTCP2_ENABLE_UDP_GSO
  }
}

void signal_write() { ev_io_start(loop_, &wev_); }

bool draining() const { return draining_; }

void start_draining_period() {
  draining_ = true;

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat =
      static_cast<ev_tstamp>(ngtcp2_conn_get_pto(conn_)) / NGTCP2_SECONDS * 3;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Draining period has started (" << timer_.repeat << " seconds)"
              << std::endl;
  }
}

int start_closing_period() {
  if (!conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
    return 0;
  }

  ev_timer_stop(loop_, &rttimer_);

  timer_.repeat =
      static_cast<ev_tstamp>(ngtcp2_conn_get_pto(conn_)) / NGTCP2_SECONDS * 3;
  ev_timer_again(loop_, &timer_);

  if (!config.quiet) {
    std::cerr << "Closing period has started (" << timer_.repeat << " seconds)"
              << std::endl;
  }

  sendbuf_.reset();
  assert(sendbuf_.left() >= max_pktlen_);

  conn_closebuf_ = std::make_unique<Buffer>(NGTCP2_MAX_PKTLEN_IPV4);

  PathStorage path;
  if (last_error_.type == QUICErrorType::Transport) {
    auto n = ngtcp2_conn_write_connection_close(
        conn_, &path.path, conn_closebuf_->wpos(), max_pktlen_,
        last_error_.code, util::timestamp(loop_));
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_connection_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    conn_closebuf_->push(n);
  } else {
    auto n = ngtcp2_conn_write_application_close(
        conn_, &path.path, conn_closebuf_->wpos(), max_pktlen_,
        last_error_.code, util::timestamp(loop_));
    if (n < 0) {
      std::cerr << "ngtcp2_conn_write_application_close: " << ngtcp2_strerror(n)
                << std::endl;
      return -1;
    }
    conn_closebuf_->push(n);
  }

  update_endpoint(&path.path.local);
  update_remote_addr(&path.path.remote);

  return 0;
}

int handle_error() {
  if (start_closing_period() != 0) {
    return -1;
  }

  if (auto rv = send_conn_close(); rv != NETWORK_ERR_OK) {
    return rv;
  }

  return NETWORK_ERR_CLOSE_WAIT;
}

int send_conn_close() {
  if (!config.quiet) {
    std::cerr << "Closing Period: TX CONNECTION_CLOSE" << std::endl;
  }

  assert(conn_closebuf_ && conn_closebuf_->size());

  if (sendbuf_.size() == 0) {
    std::copy_n(conn_closebuf_->rpos(), conn_closebuf_->size(),
                sendbuf_.wpos());
    sendbuf_.push(conn_closebuf_->size());
  }

  return server_->send_packet(*endpoint_, remote_addr_, sendbuf_.rpos(),
                              sendbuf_.size(), 0, &wev_);
}

void schedule_retransmit() {
  auto expiry = ngtcp2_conn_get_expiry(conn_);
  auto now = util::timestamp(loop_);
  auto t = expiry < now ? 1e-9
                        : static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS;
  if (!config.quiet) {
    std::cerr << "Set timer=" << std::fixed << t << "s" << std::defaultfloat
              << std::endl;
  }
  rttimer_.repeat = t;
  ev_timer_again(loop_, &rttimer_);
}

int recv_stream_data(int64_t stream_id, uint8_t fin,
                              const uint8_t *data, size_t datalen) {
  if (!config.quiet && !config.no_quic_dump) {
    debug::print_stream_data(stream_id, data, datalen);
  }

  if (!httpconn_) {
    return 0;
  }

  auto nconsumed =
      nghttp3_conn_read_stream(httpconn_, stream_id, data, datalen, fin);
  if (nconsumed < 0) {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
              << std::endl;
    last_error_ = quic_err_app(nconsumed);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

  return 0;
}

int update_key(uint8_t *rx_secret, uint8_t *tx_secret, uint8_t *rx_key,
                        uint8_t *rx_iv, uint8_t *tx_key, uint8_t *tx_iv,
                        const uint8_t *current_rx_secret,
                        const uint8_t *current_tx_secret, size_t secretlen) {
  auto crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn_);
  auto aead = &crypto_ctx->aead;
  auto keylen = ngtcp2_crypto_aead_keylen(aead);
  auto ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

  ++nkey_update_;

  if (ngtcp2_crypto_update_key(conn_, rx_secret, tx_secret, rx_key, rx_iv,
                               tx_key, tx_iv, current_rx_secret,
                               current_tx_secret, secretlen) != 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    std::cerr << "application_traffic rx secret " << nkey_update_ << std::endl;
    debug::print_secrets(rx_secret, secretlen, rx_key, keylen, rx_iv, ivlen);
    std::cerr << "application_traffic tx secret " << nkey_update_ << std::endl;
    debug::print_secrets(tx_secret, secretlen, tx_key, keylen, tx_iv, ivlen);
  }

  return 0;
}

const ngtcp2_cid *scid() const { return &scid_; }

const ngtcp2_cid *pscid() const { return &pscid_; }

const ngtcp2_cid *rcid() const { return &rcid_; }

Server *server() const { return server_; }

const Address &remote_addr() const { return remote_addr_; }

ngtcp2_conn *conn() const { return conn_; }

static
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

void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level,
                                    uint64_t offset, size_t datalen) {
  auto &crypto = crypto_[crypto_level];
  ::remove_tx_stream_data(crypto.data, crypto.acked_offset, offset + datalen);
}

int Handler::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (!config.quiet) {
    std::cerr << "QUIC stream " << stream_id << " closed" << std::endl;
  }

  if (httpconn_) {
    if (app_error_code == 0) {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
    switch (rv) {
    case 0:
      break;
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      if (ngtcp2_is_bidi_stream(stream_id)) {
        assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
        ngtcp2_conn_extend_max_streams_bidi(conn_, 1);
      }
      break;
    default:
      std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                << std::endl;
      last_error_ = quic_err_app(rv);
      return -1;
    }
  }

  return 0;
}

void shutdown_read(int64_t stream_id, int app_error_code) {
  ngtcp2_conn_shutdown_stream_read(conn_, stream_id, app_error_code);
}

void set_tls_alert(uint8_t alert) {
  last_error_ = quic_err_tls(alert);
}

private:
  TSocket *endpoint_;
  TSockAddr remote_addr_;
  size_t max_pktlen_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  Server *server_;
  ev_io wev_;
  ev_timer timer_;
  ev_timer rttimer_;
  FILE *qlog_;
  Crypto crypto_[3];
  ngtcp2_conn *conn_;
  ngtcp2_cid scid_;
  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  nghttp3_conn *httpconn_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  QUICError last_error_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  // draining_ becomes true when draining period starts.
  bool draining_;
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
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  std::vector<Endpoint> endpoints_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
public:
	QuickSocketT()
	{
			
	}

	~QuickSocketT() 
	{
		
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen, const SockAddr & stAddr) { 
		ngtcp2_pkt_hd hd;
		uint32_t version;
		const uint8_t *dcid, *scid;
		size_t dcidlen, scidlen;
		if (auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen,
													&scid, &scidlen, lpBuf,
													nBufLen, NGTCP2_SV_SCIDLEN);
			rv != 0) {
		if (rv == 1) {
			send_version_negotiation(version, scid, scidlen, dcid, dcidlen, ep,
									&su.sa, addrlen);
			continue;
		}
		std::cerr << "Could not decode version and CID from QUIC packet header: "
					<< ngtcp2_strerror(rv) << std::endl;
		continue;
		}

		auto dcid_key = util::make_cid_key(dcid, dcidlen);

		auto handler_it = handlers_.find(dcid_key);
		if (handler_it == std::end(handlers_)) {
		auto ctos_it = ctos_.find(dcid_key);
		if (ctos_it == std::end(ctos_)) {
			if (auto rv = ngtcp2_accept(&hd, buf.data(), nread); rv == -1) {
			if (!config.quiet) {
				std::cerr << "Unexpected packet received: length=" << nread
						<< std::endl;
			}
			continue;
			} else if (rv == 1) {
			if (!config.quiet) {
				std::cerr << "Unsupported version: Send Version Negotiation"
						<< std::endl;
			}
			send_version_negotiation(hd.version, hd.scid.data, hd.scid.datalen,
									hd.dcid.data, hd.dcid.datalen, ep, &su.sa,
									addrlen);
			continue;
			}

			ngtcp2_cid ocid;
			ngtcp2_cid *pocid = nullptr;
			switch (hd.type) {
			case NGTCP2_PKT_INITIAL:
			if (config.validate_addr || hd.tokenlen) {
				std::cerr << "Perform stateless address validation" << std::endl;
				if (hd.tokenlen == 0 ||
					verify_token(&ocid, &hd, &su.sa, addrlen) != 0) {
				send_retry(&hd, ep, &su.sa, addrlen);
				continue;
				}
				pocid = &ocid;
			}
			break;
			case NGTCP2_PKT_0RTT:
			send_retry(&hd, ep, &su.sa, addrlen);
			continue;
			}

			auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this, &hd.dcid);
			if (h->init(ep, &su.sa, addrlen, &hd.scid, &hd.dcid, pocid, hd.token,
						hd.tokenlen, hd.version) != 0) {
			continue;
			}

			switch (h->on_read(ep, &su.sa, addrlen, buf.data(), nread)) {
			case 0:
			break;
			case NGTCP2_ERR_RETRY:
			send_retry(&hd, ep, &su.sa, addrlen);
			continue;
			default:
			continue;
			}

			switch (h->on_write()) {
			case 0:
			case NETWORK_ERR_SEND_BLOCKED:
			break;
			default:
			continue;
			}

			auto scid = h->scid();
			auto scid_key = util::make_cid_key(scid);
			ctos_.emplace(dcid_key, scid_key);

			auto pscid = h->pscid();
			if (pscid->datalen) {
			auto pscid_key = util::make_cid_key(pscid);
			ctos_.emplace(pscid_key, scid_key);
			}

			handlers_.emplace(scid_key, std::move(h));
			continue;
		}
		if (!config.quiet) {
			std::cerr << "Forward CID=" << util::format_hex((*ctos_it).first)
					<< " to CID=" << util::format_hex((*ctos_it).second)
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
		case NETWORK_ERR_SEND_BLOCKED:
			break;
		default:
			remove(h);
		}
		continue;
		}
		if (h->draining()) {
		continue;
		}

		if (auto rv = h->on_read(ep, &su.sa, addrlen, buf.data(), nread); rv != 0) {
		if (rv != NETWORK_ERR_CLOSE_WAIT) {
			remove(h);
		}
		continue;
		}

		h->signal_write();
		return SOCKET_PACKET_FLAG_COMPLETE; }
	}

	return 0;
	}

	namespace {
	uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen,
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
	} // namespace

	int send_version_negotiation(uint32_t version, const uint8_t *dcid,
										size_t dcidlen, const uint8_t *scid,
										size_t scidlen, Endpoint &ep,
										const sockaddr *sa, socklen_t salen) {
	Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
	std::array<uint32_t, 2> sv;

	sv[0] = generate_reserved_version(sa, salen, version);
	sv[1] = NGTCP2_PROTO_VER;

	auto nwrite = ngtcp2_pkt_write_version_negotiation(
		buf.wpos(), buf.left(),
		std::uniform_int_distribution<uint8_t>(
			0, std::numeric_limits<uint8_t>::max())(randgen),
		dcid, dcidlen, scid, scidlen, sv.data(), sv.size());
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_version_negotiation: "
				<< ngtcp2_strerror(nwrite) << std::endl;
		return -1;
	}

	buf.push(nwrite);

	Address remote_addr;
	remote_addr.len = salen;
	memcpy(&remote_addr.su.sa, sa, salen);

	if (send_packet(ep, remote_addr, buf.rpos(), buf.size(), 0) !=
		NETWORK_ERR_OK) {
		return -1;
	}

	return 0;
	}

	int send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep,
						const sockaddr *sa, socklen_t salen) {
	std::array<char, NI_MAXHOST> host;
	std::array<char, NI_MAXSERV> port;

	if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
								port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
		rv != 0) {
		std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Sending Retry packet to [" << host.data()
				<< "]:" << port.data() << std::endl;
	}

	std::array<uint8_t, 256> token;
	size_t tokenlen = token.size();

	if (generate_token(token.data(), tokenlen, sa, salen, &chd->dcid) != 0) {
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Generated address validation token:" << std::endl;
		util::hexdump(stderr, token.data(), tokenlen);
	}

	Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
	ngtcp2_pkt_hd hd;

	hd.version = chd->version;
	hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
	hd.type = NGTCP2_PKT_RETRY;
	hd.pkt_num = 0;
	hd.token = nullptr;
	hd.tokenlen = 0;
	hd.len = 0;
	hd.dcid = chd->scid;
	hd.scid.datalen = NGTCP2_SV_SCIDLEN;
	auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
	std::generate(hd.scid.data, hd.scid.data + hd.scid.datalen,
					[&dis]() { return dis(randgen); });

	auto nwrite = ngtcp2_pkt_write_retry(buf.wpos(), buf.left(), &hd, &chd->dcid,
										token.data(), tokenlen);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_retry: " << ngtcp2_strerror(nwrite)
				<< std::endl;
		return -1;
	}

	buf.push(nwrite);

	Address remote_addr;
	remote_addr.len = salen;
	memcpy(&remote_addr.su.sa, sa, salen);

	if (send_packet(ep, remote_addr, buf.rpos(), buf.size(), 0) !=
		NETWORK_ERR_OK) {
		return -1;
	}

	return 0;
	}

	int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
								size_t &ivlen, const uint8_t *rand_data,
								size_t rand_datalen) {
	std::array<uint8_t, 32> secret;

	if (ngtcp2_crypto_hkdf_extract(secret.data(), secret.size(), &token_md_,
									token_secret_.data(), token_secret_.size(),
									rand_data, rand_datalen) != 0) {
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

	int generate_rand_data(uint8_t *buf, size_t len) {
	std::array<uint8_t, 16> rand;
	std::array<uint8_t, 32> md;
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

	std::copy_n(std::begin(md), len, buf);
	return 0;
	}

	int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
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

	if (generate_rand_data(rand_data.data(), rand_data.size()) != 0) {
		return -1;
	}
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

	if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
								port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
		rv != 0) {
		std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Verifying token from [" << host.data() << "]:" << port.data()
				<< std::endl;
	}

	if (!config.quiet) {
		std::cerr << "Received address validation token:" << std::endl;
		util::hexdump(stderr, hd->token, hd->tokenlen);
	}

	if (hd->tokenlen < TOKEN_RAND_DATALEN) {
		if (!config.quiet) {
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
		if (!config.quiet) {
		std::cerr << "Could not decrypt token" << std::endl;
		}
		return -1;
	}

	assert(ciphertextlen >= ngtcp2_crypto_aead_taglen(&token_aead_));

	auto plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&token_aead_);
	if (plaintextlen < salen + sizeof(uint64_t)) {
		if (!config.quiet) {
		std::cerr << "Bad token construction" << std::endl;
		}
		return -1;
	}

	auto cil = plaintextlen - salen - sizeof(uint64_t);
	if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
		if (!config.quiet) {
		std::cerr << "Bad token construction" << std::endl;
		}
		return -1;
	}

	if (memcmp(plaintext.data(), sa, salen) != 0) {
		if (!config.quiet) {
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
		if (!config.quiet) {
		std::cerr << "Token has been expired" << std::endl;
		}
		return -1;
	}

	ngtcp2_cid_init(ocid, plaintext.data() + salen + sizeof(uint64_t), cil);

	return 0;
	}

	int send_packet(Endpoint &ep, const Address &remote_addr,
							const uint8_t *data, size_t datalen, size_t gso_size,
							ev_io *wev) {
	if (debug::packet_lost(config.tx_loss_prob)) {
		if (!config.quiet) {
		std::cerr << "** Simulated outgoing packet loss **" << std::endl;
		}
		return NETWORK_ERR_OK;
	}

	iovec msg_iov;
	msg_iov.iov_base = const_cast<uint8_t *>(data);
	msg_iov.iov_len = datalen;

	msghdr msg{};
	msg.msg_name = const_cast<sockaddr *>(&remote_addr.su.sa);
	msg.msg_namelen = remote_addr.len;
	msg.msg_iov = &msg_iov;
	msg.msg_iovlen = 1;

	#if NGTCP2_ENABLE_UDP_GSO
	std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t))> msg_ctrl{};
	if (gso_size && datalen > gso_size) {
		msg.msg_control = msg_ctrl.data();
		msg.msg_controllen = msg_ctrl.size();

		auto cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_UDP;
		cm->cmsg_type = UDP_SEGMENT;
		cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
		*(reinterpret_cast<uint16_t *>(CMSG_DATA(cm))) = gso_size;
	}
	#endif // NGTCP2_ENABLE_UDP_GSO

	ssize_t nwrite = 0;

	do {
		nwrite = sendmsg(ep.fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1) {
		std::cerr << "sendmsg: " << strerror(errno) << std::endl;
		// TODO We have packet which is expected to fail to send (e.g.,
		// path validation to old path).
		return NETWORK_ERR_OK;
	}

	if (!config.quiet) {
		std::cerr << "Sent packet: local="
				<< util::straddr(&ep.addr.su.sa, ep.addr.len) << " remote="
				<< util::straddr(&remote_addr.su.sa, remote_addr.len) << " "
				<< nwrite << " bytes" << std::endl;
	}

	return NETWORK_ERR_OK;
	}

	void associate_cid(const ngtcp2_cid *cid, Handler *h) {
	ctos_.emplace(util::make_cid_key(cid), util::make_cid_key(h->scid()));
	}

	void dissociate_cid(const ngtcp2_cid *cid) {
	ctos_.erase(util::make_cid_key(cid));
	}

	void remove(const Handler *h) {
	ctos_.erase(util::make_cid_key(h->rcid()));
	ctos_.erase(util::make_cid_key(h->pscid()));

	auto conn = h->conn();
	std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(conn));
	ngtcp2_conn_get_scid(conn, cids.data());

	for (auto &cid : cids) {
		ctos_.erase(util::make_cid_key(&cid));
	}

	handlers_.erase(util::make_cid_key(h->scid()));
	}

};

/*!
 *	@brief QuickServerSocketT 定义.
 *
 *	封装QuickServerSocketT，实现Quick服务端Socket
 */
template<class TBase, class THandler>
class QuickServerSocketT : public TBase
{
	typedef QuickServerSocketT<TBase,THandler> This;
	typedef TBase Base;
public:
	typedef THandler Handler;
protected:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
public:
	QuickServerSocketT()
	{
			
	}

	~QuickServerSocketT() 
	{
		
	}
};

/*!
 *	@brief QuickClientSocketT 定义.
 *
 *	封装QuickClientSocketT，实现Quick客户端Socket
 */
template<class TBase, class THandler>
class QuickClientSocketT : public TBase
{
	typedef QuickClientSocketT<TBase,THandler> This;
	typedef TBase Base;
public:
	typedef THandler Handler;
protected:
	Address local_addr_;
	Address remote_addr_;
	size_t max_pktlen_;
	ev_io wev_;
	ev_io rev_;
	ev_timer timer_;
	ev_timer rttimer_;
	ev_timer change_local_addr_timer_;
	ev_timer key_update_timer_;
	ev_timer delay_stream_timer_;
	ev_signal sigintev_;
	struct ev_loop *loop_;
	SSL_CTX *ssl_ctx_;
	SSL *ssl_;
	int fd_;
	std::map<int64_t, std::unique_ptr<Stream>> streams_;
	Crypto crypto_[3];
	FILE *qlog_;
	ngtcp2_conn *conn_;
	nghttp3_conn *httpconn_;
	// addr_ is the server host address.
	const char *addr_;
	// port_ is the server port.
	const char *port_;
	QUICError last_error_;
	// common buffer used to store packet data before sending
	Buffer sendbuf_;
	// nstreams_done_ is the number of streams opened.
	uint64_t nstreams_done_;
	// nkey_update_ is the number of key update occurred.
	size_t nkey_update_;
	uint32_t version_;
	// early_data_ is true if client attempts to do 0RTT data transfer.
	bool early_data_;
	// should_exit_ is true if client should exit rather than waiting
	// for timeout.
	bool should_exit_;
public:
	QuickClientSocketT()
	{
			
	}

	~QuickClientSocketT() 
	{
		
	}
};

}

#endif//_H_XHTTP_IMPL_H_
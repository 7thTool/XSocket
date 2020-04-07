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
#ifndef _H_XHTTP3CLIENT_IMPL_H_
#define _H_XHTTP3CLIENT_IMPL_H_

#include "XQuicClientImpl.h"
#include "XHttp3Impl.h"

namespace XSocket
{

struct Request {
  std::string scheme;
  std::string authority;
  std::string path;
};

template <class THandler>
struct Stream
{
    typedef Stream<THandler> This;
    typedef THandler Handler;

    Handler* handler_ = nullptr;
  Request req;
  int64_t stream_id;
  int fd;

Stream(const Request &req, int64_t stream_id)
    : req(req), stream_id(stream_id), fd(-1) {}

~Stream() {
  if (fd != -1) {
    close(fd);
  }
}

int open_file(const std::string &path) {
  assert(fd == -1);

  auto it = std::find(path.rbegin(), path.rend(), '/').base();
  if (it == std::end(path)) {
    std::cerr << "No file name found: " << path << std::endl;
    return -1;
  }
  auto b = std::string{it, static_cast<size_t>(std::end(path) - it)};
  if (b == ".." || b == ".") {
    std::cerr << "Invalid file name: " << b << std::endl;
    return -1;
  }

  auto fname = std::string{handler_->get_manager()->download};
  fname += '/';
  fname += b;

  fd = open(fname.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    std::cerr << "open: Could not open file " << fname << ": "
              << strerror(errno) << std::endl;
    return -1;
  }

  return 0;
}

};

template <class T, class TManager, class TSocket, class TBase>
class Http3ClientHandler : public QuicClientHandlerT<T, TManager, TSocket, TBase>
{
    typedef QuicClientHandlerT<T, TManager, TSocket, TBase> Base;

public:
protected:
    nghttp3_conn *httpconn_ = nullptr;
    std::map<int64_t, std::unique_ptr<Stream<T>>> streams_;

public:
    Http3ClientHandler(TManager *manager, TSocket *sock_ptr, SSL_CTX *ssl_ctx):Base(manager,sock_ptr,ssl_ctx)
    {

    }
    ~Http3ClientHandler()
    {
        if (httpconn_) {
            nghttp3_conn_del(httpconn_);
            httpconn_ = nullptr;
        }
    }

int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
                   const uint8_t *tx_secret, size_t secretlen) {
  std::array<uint8_t, 64> rx_key, rx_iv, rx_hp_key, tx_key, tx_iv, tx_hp_key;

  if (ngtcp2_crypto_derive_and_install_key(
          this->conn_, this->ssl_, rx_key.data(), rx_iv.data(), rx_hp_key.data(),
          tx_key.data(), tx_iv.data(), tx_hp_key.data(), level, rx_secret,
          tx_secret, secretlen, NGTCP2_CRYPTO_SIDE_CLIENT) != 0) {
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
    // keylog::log_secret(ssl_, keylog::QUIC_CLIENT_EARLY_TRAFFIC_SECRET,
    //                    tx_secret, secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    title = "handshake_traffic";
    // keylog::log_secret(ssl_, keylog::QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET,
    //                    rx_secret, secretlen);
    // keylog::log_secret(ssl_, keylog::QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    //                    tx_secret, secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_APP:
    title = "application_traffic";
    // keylog::log_secret(ssl_, keylog::QUIC_SERVER_TRAFFIC_SECRET_0, rx_secret,
    //                    secretlen);
    // keylog::log_secret(ssl_, keylog::QUIC_CLIENT_TRAFFIC_SECRET_0, tx_secret,
    //                    secretlen);
    break;
  default:
    assert(0);
  }

//   if (!config.quiet && config.show_secret) {
//     if (rx_secret) {
//       std::cerr << title << " rx secret" << std::endl;
//       debug::print_secrets(rx_secret, secretlen, rx_key.data(), keylen,
//                            rx_iv.data(), ivlen, rx_hp_key.data(), keylen);
//     }
//     std::cerr << title << " tx secret" << std::endl;
//     debug::print_secrets(tx_secret, secretlen, tx_key.data(), keylen,
//                          tx_iv.data(), ivlen, tx_hp_key.data(), keylen);
//   }

  if (level == NGTCP2_CRYPTO_LEVEL_APP) {
    if (this->get_manager()->tp_file) {
      ngtcp2_transport_params params;

      ngtcp2_conn_get_remote_transport_params(this->conn_, &params);

      if (write_transport_params(this->get_manager()->tp_file, &params) != 0) {
        std::cerr << "Could not write transport parameters in "
                  << this->get_manager()->tp_file << std::endl;
      }
    }

    if (setup_httpconn() != 0) {
      return -1;
    }
  }

  return 0;
}

int setup_httpconn() {
  if (httpconn_) {
    return 0;
  }

  if (ngtcp2_conn_get_max_local_streams_uni(this->conn_) < 3) {
    std::cerr << "peer does not allow at least 3 unidirectional streams."
              << std::endl;
    return -1;
  }

  nghttp3_conn_callbacks callbacks{
//int http_acked_stream_data
[](nghttp3_conn *conn, int64_t stream_id,
                           size_t datalen, void *user_data,
                           void *stream_user_data) {
  auto c = static_cast<T *>(user_data);
  if (c->http_acked_stream_data(stream_id, datalen) != 0) {
    return (int)NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
      //int http_stream_close
      [](nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data) {
  auto c = static_cast<T *>(conn_user_data);
  if (c->http_stream_close(stream_id, app_error_code) != 0) {
    return (int)NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
      //int http_recv_data
      [](nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data) {
//   if (!config.quiet && !config.no_http_dump) {
//     debug::print_http_data(stream_id, data, datalen);
//   }
  auto c = static_cast<T *>(user_data);
  c->http_consume(stream_id, datalen);
  c->http_write_data(stream_id, data, datalen);
  return 0;
},          
      //int http_deferred_consume
      [](nghttp3_conn *conn, int64_t stream_id,
                          size_t nconsumed, void *user_data,
                          void *stream_user_data) {
  auto c = static_cast<T *>(user_data);
  c->http_consume(stream_id, nconsumed);
  return 0;
},
      //int http_begin_headers
      [](nghttp3_conn *conn, int64_t stream_id, void *user_data,
                       void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_begin_response_headers(stream_id);
//   }
  return 0;
},      
      //int http_recv_header
      [](nghttp3_conn *conn, int64_t stream_id, int32_t token,
                     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                     void *user_data, void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_header(stream_id, name, value, flags);
//   }
  return 0;
},
      //int http_end_headers
      [](nghttp3_conn *conn, int64_t stream_id, void *user_data,
                     void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_end_headers(stream_id);
//   }
  return 0;
},        
      //int http_begin_trailers
      [](nghttp3_conn *conn, int64_t stream_id, void *user_data,
                        void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_begin_trailers(stream_id);
//   }
  return 0;
},
      //int http_recv_trailer
      [](nghttp3_conn *conn, int64_t stream_id, int32_t token,
                      nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                      void *user_data, void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_header(stream_id, name, value, flags);
//   }
  return 0;
},       
      //int http_end_trailers
      [](nghttp3_conn *conn, int64_t stream_id, void *user_data,
                      void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_end_trailers(stream_id);
//   }
  return 0;
},
      //int http_begin_push_promise
      [](nghttp3_conn *conn, int64_t stream_id,
                            int64_t push_id, void *user_data,
                            void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_begin_push_promise(stream_id, push_id);
//   }
  return 0;
}, 
      //int http_recv_push_promise
      [](nghttp3_conn *conn, int64_t stream_id,
                           int64_t push_id, int32_t token, nghttp3_rcbuf *name,
                           nghttp3_rcbuf *value, uint8_t flags, void *user_data,
                           void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_push_promise(stream_id, push_id, name, value, flags);
//   }
  return 0;
},
      //int http_end_push_promise
      [](nghttp3_conn *conn, int64_t stream_id,
                          int64_t push_id, void *user_data,
                          void *stream_user_data) {
//   if (!config.quiet) {
//     debug::print_http_end_push_promise(stream_id, push_id);
//   }
  return 0;
},   
      //int http_cancel_push
      [](nghttp3_conn *conn, int64_t push_id, int64_t stream_id,
                     void *user_data, void *stream_user_data) {
//   if (!config.quiet) {
//     debug::cancel_push(push_id, stream_id);
//   }
  return 0;
},
      //int http_send_stop_sending
      [](nghttp3_conn *conn, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  auto c = static_cast<T *>(user_data);
  if (c->send_stop_sending(stream_id, app_error_code) != 0) {
    return (int)NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
},  
      //int http_push_stream
      [](nghttp3_conn *conn, int64_t push_id, int64_t stream_id,
                     void *user_data) {
//   if (!config.quiet) {
//     debug::push_stream(push_id, stream_id);
//   }
  return 0;
},
  };
  nghttp3_conn_settings settings;
  nghttp3_conn_settings_default(&settings);
  settings.qpack_max_table_capacity = 4096;
  settings.qpack_blocked_streams = 100;
  settings.max_pushes = 100;

  auto mem = nghttp3_mem_default();

  auto rv = nghttp3_conn_client_new(&httpconn_, &callbacks, &settings, mem, this);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_client_new: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  int64_t ctrl_stream_id;
  rv = ngtcp2_conn_open_uni_stream(this->conn_, &ctrl_stream_id, nullptr);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = nghttp3_conn_bind_control_stream(httpconn_, ctrl_stream_id); 
  if (rv != 0) {
    std::cerr << "nghttp3_conn_bind_control_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (IsDebug()) {
    fprintf(stderr, "http: control stream=%" PRIx64 "\n", ctrl_stream_id);
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;
  rv = ngtcp2_conn_open_uni_stream(this->conn_, &qpack_enc_stream_id, nullptr);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream(this->conn_, &qpack_dec_stream_id, nullptr); 
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = nghttp3_conn_bind_qpack_streams(httpconn_, qpack_enc_stream_id, qpack_dec_stream_id);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_bind_qpack_streams: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (IsDebug()) {
    fprintf(stderr,
            "http: QPACK streams encoder=%" PRIx64 " decoder=%" PRIx64 "\n",
            qpack_enc_stream_id, qpack_dec_stream_id);
  }

  return 0;
}

int http_acked_stream_data(int64_t stream_id, size_t datalen) {
  return 0;
}

int http_stream_close(int64_t stream_id, uint64_t app_error_code) {
//   if (config.exit_on_first_stream_close) {
//     should_exit_ = true;
//   }

  if (!ngtcp2_is_bidi_stream(stream_id)) {
    assert(!ngtcp2_conn_is_local_stream(this->conn_, stream_id));
    ngtcp2_conn_extend_max_streams_uni(this->conn_, 1);
  }

auto it = this->streams_.find(stream_id);
  if (it != std::end(this->streams_)) {
    if (IsDebug()) {
      std::cerr << "HTTP stream " << stream_id << " closed with error code "
                << app_error_code << std::endl;
    }
    this->streams_.erase(it);
  }

  return 0;
}

void http_consume(int64_t stream_id, size_t nconsumed) {
  ngtcp2_conn_extend_max_stream_offset(this->conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(this->conn_, nconsumed);
}

void http_write_data(int64_t stream_id, const uint8_t *data,
                             size_t datalen) {
  auto it = this->streams_.find(stream_id);
  if (it == std::end(this->streams_)) {
    return;
  }

  auto &stream = (*it).second;

  if (stream->fd == -1) {
    return;
  }

  ssize_t nwrite;
  do {
    nwrite = write(stream->fd, data, datalen);
  } while (nwrite == -1 && errno == EINTR);
}

int send_stop_sending(int64_t stream_id, uint64_t app_error_code) {
    auto rv =
          ngtcp2_conn_shutdown_stream_read(this->conn_, stream_id, app_error_code);
  if ( rv != 0) {
    std::cerr << "ngtcp2_conn_shutdown_stream_read: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

int extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
    auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); 
  if (rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

int write_streams() {
  std::array<nghttp3_vec, 16> vec;
  PathStorage path;
  size_t pktcnt = 0;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize sveccnt = 0;

    if (httpconn_ && ngtcp2_conn_get_max_data_left(this->conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                  << std::endl;
        this->last_error_ = quic_err_app(sveccnt);
        disconnect();
        return -1;
      }
    }

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    auto nwrite = ngtcp2_conn_writev_stream(
        this->conn_, &path.path, this->sendbuf_.wpos(), this->max_pktlen_, &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, timestamp());
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
      {
        assert(ndatalen == -1);
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED &&
            ngtcp2_conn_get_max_data_left(this->conn_) == 0) {
          return 0;
        }

        auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          this->last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
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
          this->last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
        }
        continue;
      }
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      this->last_error_ = quic_err_transport(nwrite);
      disconnect();
      return -1;
    }

    if (nwrite == 0) {
      // We are congestion limited.
      return 0;
    }

    this->sendbuf_.push(nwrite);

    update_remote_addr(&path.path.remote);
    // reset_idle_timer();

    // if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
    //   return rv;
    // }

    // if (++pktcnt == 10) {
    //   ev_io_start(loop_, &wev_);
    //   return 0;
    // }
  }
}

int on_stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (httpconn_) {
    if (app_error_code == 0) {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
    switch (rv) {
    case 0:
      break;
    /*case NGHTTP3_ERR_STREAM_NOT_FOUND:
      // We have to handle the case when stream opened but no data is
      // transferred.  In this case, nghttp3_conn_close_stream might
      // return error.
      if (!ngtcp2_is_bidi_stream(stream_id)) {
        assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
        ngtcp2_conn_extend_max_streams_uni(conn_, 1);
      }
      break;*/
    default:
      std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                << std::endl;
      this->last_error_ = quic_err_app(rv);
      return -1;
    }
  }

  return 0;
}

int on_stream_reset(int64_t stream_id) {
  if (httpconn_) {
    auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id); 
    if (rv != 0) {
      std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

int submit_http_request(const Stream<T> *stream) {
  std::string content_length_str;

  const auto &req = stream->req;

  std::array<nghttp3_nv, 6> nva{
      make_nv(":method", "GET"),
      make_nv(":scheme", req.scheme),
      make_nv(":authority", req.authority),
      make_nv(":path", req.path),
      make_nv("user-agent", "nghttp3/ngtcp2 client"),
  };
  size_t nvlen = 5;
  if (this->fd != -1) {
    content_length_str = std::to_string(this->datalen);
    nva[nvlen++] = make_nv("content-length", content_length_str);
  }

//   if (!config.quiet) {
//     debug::print_http_request_headers(stream->stream_id, nva.data(), nvlen);
//   }

  nghttp3_data_reader dr{};
  dr.read_data = //nghttp3_ssize read_data
  [](nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data,
                        void *stream_user_data) {
  //auto stream = static_cast<Stream<T> *>(stream_user_data);
  return 1;
};

  auto rv = nghttp3_conn_submit_request(
          httpconn_, stream->stream_id, nva.data(), nvlen,
          this->get_manager()->fd == -1 ? nullptr : &dr, nullptr);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_submit_request: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

int recv_stream_data(int64_t stream_id, int fin, const uint8_t *data,
                             size_t datalen) {
  auto nconsumed =
      nghttp3_conn_read_stream(httpconn_, stream_id, data, datalen, fin);
  if (nconsumed < 0) {
    std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
              << std::endl;
    this->last_error_ = quic_err_app(nconsumed);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(this->conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(this->conn_, nconsumed);

  return 0;
}

int acked_stream_data_offset(int64_t stream_id, size_t datalen) {
  auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
  if (rv != 0) {
    std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  return 0;
}

};

/*!
 *	@brief QuicServerManagerT 定义.
 *
 *	封装QuicServerManagerT，实现Quick服务
 */
template <class T, class TSocket, class THandler>
class Http3ClientManagerT : public QuicClientManagerT<T, TSocket, THandler> {
  typedef Http3ClientManagerT<T, TSocket, THandler> This;
  typedef QuicClientManagerT<T, TSocket, THandler> Base;

 public:
  typedef THandler Handler;

 protected:
 public:
  Http3ClientManagerT(int max_handlerset_count): Base(max_handlerset_count) {}

  ~Http3ClientManagerT() {}

  // fd is a file descriptor to read input for streams.
  int fd;
  // data is the pointer to memory region which maps file denoted by
  // fd.
  uint8_t *data;
  // datalen is the length of file denoted by fd.
  size_t datalen;

  std::string http_method;
  // download is a path to a directory where a downloaded file is
  // saved.  If it is empty, no file is saved.
  std::string download;
  // requests contains URIs to request.
  std::vector<Request> requests;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump;
};

} // namespace XSocket

#endif //_H_XHTTP3CLIENT_IMPL_H_
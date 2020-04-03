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

#include "XSocketImpl.h"
#include "XHttp2Impl.h"
#include "XQuicImpl.h"
#include <nghttp3/nghttp3.h>

namespace XSocket
{

namespace
{

template <typename T, size_t N1, size_t N2>
constexpr nghttp3_nv make_nv(const T (&name)[N1], const T (&value)[N2])
{
    return nghttp3_nv{(uint8_t *)name, (uint8_t *)value, N1 - 1, N2 - 1,
                      NGHTTP3_NV_FLAG_NONE};
}

template <typename T, size_t N, typename S>
constexpr nghttp3_nv make_nv(const T (&name)[N], const S &value)
{
    return nghttp3_nv{(uint8_t *)name, (uint8_t *)value.data(), N - 1,
                      value.size(), NGHTTP3_NV_FLAG_NONE};
}

template <typename S1, typename S2>
constexpr nghttp3_nv make_nv(const S1 &name, const S2 &value)
{
    return nghttp3_nv{(uint8_t *)name.data(), (uint8_t *)value.data(),
                      name.size(), value.size(), NGHTTP3_NV_FLAG_NONE};
}

} // namespace

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

  auto it = std::find(std::rbegin(path), std::rend(path), '/').base();
  if (it == std::end(path)) {
    std::cerr << "No file name found: " << path << std::endl;
    return -1;
  }
  auto b = std::string{it, static_cast<size_t>(std::end(path) - it)};
  if (b == ".." || b == ".") {
    std::cerr << "Invalid file name: " << b << std::endl;
    return -1;
  }

  auto fname = std::string{config.download};
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
    ~Http2ClientHandler()
    {
        if (httpconn_) {
            nghttp3_conn_del(httpconn_);
            httpconn_ = nullptr;
        }
    }

int setup_httpconn() {
  if (httpconn_) {
    return 0;
  }

  if (ngtcp2_conn_get_max_local_streams_uni(conn_) < 3) {
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
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
},
      //int http_stream_close
      [](nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data) {
  auto c = static_cast<T *>(conn_user_data);
  if (c->http_stream_close(stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
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
    return NGHTTP3_ERR_CALLBACK_FAILURE;
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
  rv = ngtcp2_conn_open_uni_stream(conn_, &ctrl_stream_id, nullptr);
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
  rv = ngtcp2_conn_open_uni_stream(conn_, &qpack_enc_stream_id, nullptr);
  if (rv != 0) {
    std::cerr << "ngtcp2_conn_open_uni_stream: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream(conn_, &qpack_dec_stream_id, nullptr); 
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

    if (httpconn_ && ngtcp2_conn_get_max_data_left(conn_)) {
      sveccnt = nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin,
                                           vec.data(), vec.size());
      if (sveccnt < 0) {
        std::cerr << "nghttp3_conn_writev_stream: " << nghttp3_strerror(sveccnt)
                  << std::endl;
        last_error_ = quic_err_app(sveccnt);
        disconnect();
        return -1;
      }
    }

    ngtcp2_ssize ndatalen;
    auto v = vec.data();
    auto vcnt = static_cast<size_t>(sveccnt);

    auto nwrite = ngtcp2_conn_writev_stream(
        conn_, &path.path, sendbuf_.wpos(), max_pktlen_, &ndatalen,
        NGTCP2_WRITE_STREAM_FLAG_MORE, stream_id, fin,
        reinterpret_cast<const ngtcp2_vec *>(v), vcnt, timestamp(loop_));
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        assert(ndatalen == -1);
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED &&
            ngtcp2_conn_get_max_data_left(conn_) == 0) {
          return 0;
        }

        auto rv = nghttp3_conn_block_stream(httpconn_, stream_id);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_block_stream: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
        }
        continue;
      case NGTCP2_ERR_WRITE_STREAM_MORE:
        assert(ndatalen > 0);
        auto rv = nghttp3_conn_add_write_offset(httpconn_, stream_id, ndatalen);
        if (rv != 0) {
          std::cerr << "nghttp3_conn_add_write_offset: " << nghttp3_strerror(rv)
                    << std::endl;
          last_error_ = quic_err_app(rv);
          disconnect();
          return -1;
        }
        continue;
      }

      assert(ndatalen == -1);

      std::cerr << "ngtcp2_conn_write_stream: " << ngtcp2_strerror(nwrite)
                << std::endl;
      last_error_ = quic_err_transport(nwrite);
      disconnect();
      return -1;
    }

    if (nwrite == 0) {
      // We are congestion limited.
      return 0;
    }

    sendbuf_.push(nwrite);

    update_remote_addr(&path.path.remote);
    reset_idle_timer();

    if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
      return rv;
    }

    if (++pktcnt == 10) {
      ev_io_start(loop_, &wev_);
      return 0;
    }
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
      last_error_ = quic_err_app(rv);
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

int submit_http_request(const Stream *stream) {
  std::string content_length_str;

  const auto &req = stream->req;

  std::array<nghttp3_nv, 6> nva{
      make_nv(":method", config.http_method),
      make_nv(":scheme", req.scheme),
      make_nv(":authority", req.authority),
      make_nv(":path", req.path),
      make_nv("user-agent", "nghttp3/ngtcp2 client"),
  };
  size_t nvlen = 5;
  if (config.fd != -1) {
    content_length_str = std::to_string(config.datalen);
    nva[nvlen++] = make_nv("content-length", content_length_str);
  }

//   if (!config.quiet) {
//     debug::print_http_request_headers(stream->stream_id, nva.data(), nvlen);
//   }

  nghttp3_data_reader dr{};
  dr.read_data = read_data;

  auto rv = nghttp3_conn_submit_request(
          httpconn_, stream->stream_id, nva.data(), nvlen,
          config.fd == -1 ? nullptr : &dr, nullptr);
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
    last_error_ = quic_err_app(nconsumed);
    return -1;
  }

  ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(conn_, nconsumed);

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

} // namespace XSocket

#endif //_H_XHTTP3_IMPL_H_
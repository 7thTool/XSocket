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
#ifndef _H_XHTTP3_IMPL_H_
#define _H_XHTTP3_IMPL_H_

#include "XSocketImpl.h"
#include "XHttp2Impl.h"
#include "XQuicImpl.h"
#include <nghttp3/nghttp3.h>

namespace XSocket {

namespace {

template <typename T, size_t N1, size_t N2>
constexpr nghttp3_nv make_nv(const T (&name)[N1], const T (&value)[N2]) {
  return nghttp3_nv{(uint8_t *)name, (uint8_t *)value, N1 - 1, N2 - 1,
                    NGHTTP3_NV_FLAG_NONE};
}

template <typename T, size_t N, typename S>
constexpr nghttp3_nv make_nv(const T (&name)[N], const S &value) {
  return nghttp3_nv{(uint8_t *)name, (uint8_t *)value.data(), N - 1,
                    value.size(), NGHTTP3_NV_FLAG_NONE};
}

template <typename S1, typename S2>
constexpr nghttp3_nv make_nv(const S1 &name, const S2 &value) {
  return nghttp3_nv{(uint8_t *)name.data(), (uint8_t *)value.data(),
                    name.size(), value.size(), NGHTTP3_NV_FLAG_NONE};
}

} // namespace

template<class THandler>
struct Stream 
{
typedef Stream<THandler> This;
typedef THandler Handler;

Stream(int64_t stream_id, Handler *handler)
    : stream_id(stream_id),
      handler(handler),
      fd(-1),
      data(nullptr),
      datalen(0),
      dynresp(false),
      dyndataleft(0),
      dynbuflen(0),
      mmapped(false) {}

~Stream() {
  if (mmapped) {
    munmap(data, datalen);
  }
  if (fd != -1) {
    close(fd);
  }
}

nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data) {
  vec[0].base = data;
  vec[0].len = datalen;
  *pflags |= NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM;

  return 1;
}

nghttp3_ssize dyn_read_data(nghttp3_conn *conn, int64_t stream_id,
                            nghttp3_vec *vec, size_t veccnt, uint32_t *pflags, void *user_data) {
  if (dynbuflen > MAX_DYNBUFLEN) {
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  static auto dyn_buf = std::unique_ptr<std::array<uint8_t, 16_k>>(new std::array<uint8_t, 16_k>());

  auto len =
      std::min(dyn_buf->size(), static_cast<size_t>(dyndataleft));

  vec[0].base = dyn_buf->data();
  vec[0].len = len;

  dynbuflen += len;
  dyndataleft -= len;

  if (dyndataleft == 0) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM;
    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 1> trailers{
        make_nv("x-ngtcp2-stream-id", stream_id_str),
    };

    auto rv = nghttp3_conn_submit_trailers(conn, stream_id, trailers.data(),
                                               trailers.size());
    if (rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  return 1;
}

int start_response(nghttp3_conn *httpconn) {
  // TODO This should be handled by nghttp3
  if (uri.empty() || method.empty()) {
    return send_status_response(httpconn, 400);
  }

  auto req = request_path(uri, method == "CONNECT");
  if (req.path.empty()) {
    return send_status_response(httpconn, 400);
  }

  auto dyn_len = find_dyn_length(req.path);

  int64_t content_length = -1;
  nghttp3_data_reader dr{};
  std::string content_type = "text/plain";

  if (dyn_len == -1) {
    auto path = resolve_path(req.path);
    if (path.empty() || open_file(path) != 0) {
      send_status_response(httpconn, 404);
      return 0;
    }

    struct stat st {};

    if (fstat(fd, &st) == 0) {
      if (st.st_mode & S_IFDIR) {
        send_redirect_response(httpconn, 308,
                               path.substr(config.htdocs.size() - 1) + '/');
        return 0;
      }
      content_length = st.st_size;
    } else {
      send_status_response(httpconn, 404);
      return 0;
    }

    if (method == "HEAD") {
      close(fd);
      fd = -1;
    } else if (map_file(content_length) != 0) {
      send_status_response(httpconn, 500);
      return 0;
    }

    dr.read_data = [](nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                      size_t veccnt, uint32_t *pflags, void *user_data,
                      void *stream_user_data) {
        auto stream = static_cast<This *>(stream_user_data);
        return stream->read_data(conn, stream_id, vec, veccnt, pflags, user_data);
    };

    auto ext = std::end(req.path) - 1;
    for (; ext != std::begin(req.path) && *ext != '.' && *ext != '/'; --ext)
      ;
    if (*ext == '.') {
      ++ext;
      auto it = config.mime_types.find(std::string{ext, std::end(req.path)});
      if (it != std::end(config.mime_types)) {
        content_type = (*it).second;
      }
    }

  } else {
    content_length = dyn_len;
    datalen = dyn_len;
    dynresp = true;
    dyndataleft = dyn_len;

    dr.read_data = [](nghttp3_conn *conn, int64_t stream_id,
                      nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                      void *user_data, void *stream_user_data) {
        auto stream = static_cast<This *>(stream_user_data);
        return stream->dyn_read_data(conn, stream_id, vec, veccnt, pflags, user_data);
    };

    content_type = "application/octet-stream";
  }

  if ((stream_id & 0x3) == 0 && !authority.empty()) {
    for (const auto &push : req.pushes) {
      if (handler->push_content(stream_id, authority, push) != 0) {
        return -1;
      }
    }
  }

  auto content_length_str = std::to_string(content_length);

  std::array<nghttp3_nv, 4> nva{
      make_nv(":status", "200"),
      make_nv("server", NGTCP2_SERVER),
      make_nv("content-type", content_type),
      make_nv("content-length", content_length_str),
  };

//   if (!config.quiet) {
//     debug::print_http_response_headers(stream_id, nva.data(), nva.size());
//   }

  if (auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                             nva.size(), &dr);
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  if (dyn_len == -1) {
    auto stream_id_str = std::to_string(stream_id);
    std::array<nghttp3_nv, 1> trailers{
        make_nv("x-ngtcp2-stream-id", stream_id_str),
    };

    auto rv = nghttp3_conn_submit_trailers(
            httpconn, stream_id, trailers.data(), trailers.size());
    if (rv != 0) {
      std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }

    handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);
  }

  return 0;
}

  
int open_file(const std::string &path) {
  fd = open(path.c_str(), O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  return 0;
}

int map_file(size_t len) {
  if (len == 0) {
    return 0;
  }
  data =
      static_cast<uint8_t *>(mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0));
  if (data == MAP_FAILED) {
    std::cerr << "mmap: " << strerror(errno) << std::endl;
    return -1;
  }
  datalen = len;
  mmapped = true;
  return 0;
}

int send_status_response(nghttp3_conn *httpconn,
                                 unsigned int status_code,
                                 const std::vector<HttpHeader> &extra_headers = {}) {
  status_resp_body = make_status_body(status_code);

  auto status_code_str = std::to_string(status_code);
  auto content_length_str = std::to_string(status_resp_body.size());

  std::vector<nghttp3_nv> nva(4 + extra_headers.size());
  nva[0] = make_nv(":status", status_code_str);
  nva[1] = make_nv("server", NGTCP2_SERVER);
  nva[2] = make_nv("content-type", "text/html; charset=utf-8");
  nva[3] = make_nv("content-length", content_length_str);
  for (size_t i = 0; i < extra_headers.size(); ++i) {
    auto &hdr = extra_headers[i];
    auto &nv = nva[4 + i];
    nv = make_nv(hdr.name, hdr.value);
  }

  data = (uint8_t *)status_resp_body.data();
  datalen = status_resp_body.size();

  nghttp3_data_reader dr{};
  dr.read_data = [](nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                      size_t veccnt, uint32_t *pflags, void *user_data,
                      void *stream_user_data) {
        auto stream = static_cast<This *>(stream_user_data);
        return stream->read_data(conn, stream_id, vec, veccnt, pflags, user_data);
    };

  if (auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                             nva.size(), &dr);
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  auto stream_id_str = std::to_string(stream_id);
  std::array<nghttp3_nv, 1> trailers{
      make_nv("x-ngtcp2-stream-id", stream_id_str),
  };

  if (auto rv = nghttp3_conn_submit_trailers(httpconn, stream_id,
                                             trailers.data(), trailers.size());
      rv != 0) {
    std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }

  handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);

  return 0;
}

int send_redirect_response(nghttp3_conn *httpconn,
                                   unsigned int status_code,
                                   const std::string &path) {
  return send_status_response(httpconn, status_code, {{"location", path}});
}

  
int64_t find_dyn_length(const std::string &path) {
  assert(path[0] == '/');

  uint64_t n = 0;

  for (auto it = std::begin(path) + 1; it != std::end(path); ++it) {
    if (*it < '0' || '9' < *it) {
      return -1;
    }
    auto d = *it - '0';
    if (n > (((1ull << 62) - 1) - d) / 10) {
      return -1;
    }
    n = n * 10 + d;
    if (n > config.max_dyn_length) {
      return -1;
    }
  }

  return static_cast<int64_t>(n);
}
  
void http_acked_stream_data(size_t datalen) {
  if (!dynresp) {
    return;
  }

  assert(dynbuflen >= datalen);

  dynbuflen -= datalen;
}

  int64_t stream_id;
  Handler *handler;
  // uri is request uri/path.
  std::string uri;
  std::string method;
  std::string authority;
  // fd is a file descriptor to read file to send its content to a
  // client.
  int fd;
  std::string status_resp_body;
  // data is a pointer to the memory which maps file denoted by fd.
  uint8_t *data;
  // datalen is the length of mapped file by data.
  uint64_t datalen;
  // dynresp is true if dynamic data response is enabled.
  bool dynresp;
  // dyndataleft is the number of dynamic data left to send.
  uint64_t dyndataleft;
  // dynbuflen is the number of bytes in-flight.
  uint64_t dynbuflen;
  // mmapped is true if data points to the memory assigned by mmap.
  bool mmapped;
};


    template<class T, class TManager, class TSocket, class TBase>
    class Http3Handler : public QuicHandler<T,TManager,TSocket,TBase>
    {
        typedef QuicHandler<T,TManager,TSocket,TBase> Base;
    public:
    protected:
        nghttp3_conn *httpconn_;
        std::map<int64_t, std::unique_ptr<Stream<T>>> streams_;
    public:

virtual int recv_stream_data(int64_t stream_id, uint8_t fin,
                              const uint8_t *data, size_t datalen) {
  // if (!config.quiet && !config.no_quic_dump) {
  //   debug::print_stream_data(stream_id, data, datalen);
  // }

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

virtual int acked_stream_data_offset(int64_t stream_id, size_t datalen) {
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

virtual int on_stream_close(int64_t stream_id, uint64_t app_error_code) {
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

virtual void extend_max_remote_streams_bidi(uint64_t max_streams) {
  if (!httpconn_) {
    return;
  }

  nghttp3_conn_set_max_client_streams_bidi(httpconn_, max_streams);
}

virtual int extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
  if (auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id); rv != 0) {
    std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
              << std::endl;
    return -1;
  }
  return 0;
}

virtual int on_stream_reset(int64_t stream_id) {
  if (httpconn_) {
    if (auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id); rv != 0) {
      std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                << std::endl;
      return -1;
    }
  }
  return 0;
}

    };
}

#endif//_H_XHTTP3_IMPL_H_
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
#ifndef _H_XHTTP3SERVER_IMPL_H_
#define _H_XHTTP3SERVER_IMPL_H_

#include "XQuicServerImpl.h"
#include "XHttp3Impl.h"
#include <sys/mman.h>

namespace XSocket
{

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

template <typename S, typename T> bool istarts_with(const S &a, const T &b) {
  return istarts_with(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, typename CharT, size_t N>
bool istarts_with_l(const T &a, const CharT (&b)[N]) {
  return istarts_with(a.begin(), a.end(), b, b + N - 1);
}

struct Request
{
    std::string path;
    std::vector<std::string> pushes;
};

namespace
{
Request request_path(const std::string &uri, bool is_connect)
{
    http_parser_url u;
    Request req;

    http_parser_url_init(&u);

    auto rv = http_parser_parse_url(uri.data(), uri.size(), is_connect, &u);
    if (rv != 0)
    {
        return req;
    }

    if (u.field_set & (1 << UF_PATH))
    {
        req.path = std::string(uri.data() + u.field_data[UF_PATH].off,
                               u.field_data[UF_PATH].len);
        if (!req.path.empty() && req.path.back() == '/')
        {
            req.path += "index.html";
        }
    }
    else
    {
        req.path = "/index.html";
    }

    if (u.field_set & (1 << UF_QUERY))
    {
        static constexpr char push_prefix[] = "push=";
        auto q = std::string(uri.data() + u.field_data[UF_QUERY].off,
                             u.field_data[UF_QUERY].len);
        for (auto p = std::begin(q); p != std::end(q);)
        {
            if (!istarts_with(p, std::end(q), std::begin(push_prefix),
                                    std::end(push_prefix) - 1))
            {
                p = std::find(p, std::end(q), '&');
                if (p == std::end(q))
                {
                    break;
                }
                ++p;
                continue;
            }

            auto path_start = p + sizeof(push_prefix) - 1;
            auto path_end = std::find(path_start, std::end(q), '&');
            if (path_start != path_end && *path_start == '/')
            {
                req.pushes.emplace_back(path_start, path_end);
            }
            if (path_end == std::end(q))
            {
                break;
            }
            p = path_end + 1;
        }
    }
    return req;
}
} // namespace

template <class THandler>
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

    ~Stream()
    {
        if (mmapped)
        {
            munmap(data, datalen);
        }
        if (fd != -1)
        {
            close(fd);
        }
    }

    nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                            size_t veccnt, uint32_t *pflags, void *user_data)
    {
        vec[0].base = data;
        vec[0].len = datalen;
        *pflags |= NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM;

        return 1;
    }

    nghttp3_ssize dyn_read_data(nghttp3_conn *conn, int64_t stream_id,
                                nghttp3_vec *vec, size_t veccnt, uint32_t *pflags, void *user_data)
    {
        if (dynbuflen > MAX_DYNBUFLEN)
        {
            return NGHTTP3_ERR_WOULDBLOCK;
        }

        static auto dyn_buf = std::unique_ptr<std::array<uint8_t, 16_k>>(new std::array<uint8_t, 16_k>());

        auto len =
            std::min(dyn_buf->size(), static_cast<size_t>(dyndataleft));

        vec[0].base = dyn_buf->data();
        vec[0].len = len;

        dynbuflen += len;
        dyndataleft -= len;

        if (dyndataleft == 0)
        {
            *pflags |= NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM;
            auto stream_id_str = std::to_string(stream_id);
            std::array<nghttp3_nv, 1> trailers{
                make_nv("x-ngtcp2-stream-id", stream_id_str),
            };

            auto rv = nghttp3_conn_submit_trailers(conn, stream_id, trailers.data(),
                                                   trailers.size());
            if (rv != 0)
            {
                std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                          << std::endl;
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
        }

        return 1;
    }

    std::string resolve_path(const std::string &req_path)
    {
        auto& docs = handler->manager()->docs;
        auto raw_path = docs + req_path;
        std::array<char, PATH_MAX> buf;
        auto p = realpath(raw_path.c_str(), buf.data());
        if (p == nullptr)
        {
            return "";
        }
        auto path = std::string(p);

        if (path.size() < docs.size() ||
            !std::equal(std::begin(docs), std::end(docs),
                        std::begin(path)))
        {
            return "";
        }
        return path;
    }

    std::string make_status_body(unsigned int status_code)
    {
        auto status_string = std::to_string(status_code);
        auto reason_phrase = http_status_str((enum http_status)status_code);

        std::string body;
        body = "<html><head><title>";
        body += status_string;
        body += ' ';
        body += reason_phrase;
        body += "</title></head><body><h1>";
        body += status_string;
        body += ' ';
        body += reason_phrase;
        body += "</h1><hr><address>";
        body += handler->manager()->server;
        body += " at port ";
        body += handler->manager()->port;
        body += "</address>";
        body += "</body></html>";
        return body;
    }

    int start_response(nghttp3_conn *httpconn)
    {
        // TODO This should be handled by nghttp3
        if (uri.empty() || method.empty())
        {
            return send_status_response(httpconn, 400);
        }

        auto req = request_path(uri, method == "CONNECT");
        if (req.path.empty())
        {
            return send_status_response(httpconn, 400);
        }

        auto dyn_len = find_dyn_length(req.path);

        int64_t content_length = -1;
        nghttp3_data_reader dr{};
        std::string content_type = "text/plain";

        if (dyn_len == -1)
        {
            auto path = resolve_path(req.path);
            if (path.empty() || open_file(path) != 0)
            {
                send_status_response(httpconn, 404);
                return 0;
            }

            struct stat st
            {
            };

            if (fstat(fd, &st) == 0)
            {
                if (st.st_mode & S_IFDIR)
                {
                    send_redirect_response(httpconn, 308,
                                           path.substr(handler->manager()->docs.size() - 1) + '/');
                    return 0;
                }
                content_length = st.st_size;
            }
            else
            {
                send_status_response(httpconn, 404);
                return 0;
            }

            if (method == "HEAD")
            {
                close(fd);
                fd = -1;
            }
            else if (map_file(content_length) != 0)
            {
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
            if (*ext == '.')
            {
                ++ext;
                auto& mime_types = handler->manager()->mime_types;
                auto it = mime_types.find(std::string{ext, std::end(req.path)});
                if (it != std::end(mime_types))
                {
                    content_type = (*it).second;
                }
            }
        }
        else
        {
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

        if ((stream_id & 0x3) == 0 && !authority.empty())
        {
            for (const auto &push : req.pushes)
            {
                if (handler->push_content(stream_id, authority, push) != 0)
                {
                    return -1;
                }
            }
        }

        auto content_length_str = std::to_string(content_length);

        std::array<nghttp3_nv, 4> nva{
            make_nv(":status", "200"),
            make_nv("server", handler->manager()->server),
            make_nv("content-type", content_type),
            make_nv("content-length", content_length_str),
        };

        //   if (!config.quiet) {
        //     debug::print_http_response_headers(stream_id, nva.data(), nva.size());
        //   }

        auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                                   nva.size(), &dr);
        if (rv != 0)
        {
            std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
                      << std::endl;
            return -1;
        }

        if (dyn_len == -1)
        {
            auto stream_id_str = std::to_string(stream_id);
            std::array<nghttp3_nv, 1> trailers{
                make_nv("x-ngtcp2-stream-id", stream_id_str),
            };

            auto rv = nghttp3_conn_submit_trailers(
                httpconn, stream_id, trailers.data(), trailers.size());
            if (rv != 0)
            {
                std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                          << std::endl;
                return -1;
            }

            handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);
        }

        return 0;
    }

    int open_file(const std::string &path)
    {
        fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
        {
            return -1;
        }

        return 0;
    }

    int map_file(size_t len)
    {
        if (len == 0)
        {
            return 0;
        }
        data =
            static_cast<uint8_t *>(mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0));
        if (data == MAP_FAILED)
        {
            std::cerr << "mmap: " << strerror(errno) << std::endl;
            return -1;
        }
        datalen = len;
        mmapped = true;
        return 0;
    }

    int send_status_response(nghttp3_conn *httpconn,
                             unsigned int status_code,
                             const std::vector<HttpHeader> &extra_headers = {})
    {
        status_resp_body = make_status_body(status_code);

        auto status_code_str = std::to_string(status_code);
        auto content_length_str = std::to_string(status_resp_body.size());

        std::vector<nghttp3_nv> nva(4 + extra_headers.size());
        nva[0] = make_nv(":status", status_code_str);
        nva[1] = make_nv("server", handler->manager()->server);
        nva[2] = make_nv("content-type", "text/html; charset=utf-8");
        nva[3] = make_nv("content-length", content_length_str);
        for (size_t i = 0; i < extra_headers.size(); ++i)
        {
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

        auto rv = nghttp3_conn_submit_response(httpconn, stream_id, nva.data(),
                                                   nva.size(), &dr);
        if (rv != 0)
        {
            std::cerr << "nghttp3_conn_submit_response: " << nghttp3_strerror(rv)
                      << std::endl;
            return -1;
        }

        auto stream_id_str = std::to_string(stream_id);
        std::array<nghttp3_nv, 1> trailers{
            make_nv("x-ngtcp2-stream-id", stream_id_str),
        };

        rv = nghttp3_conn_submit_trailers(httpconn, stream_id,
                                                   trailers.data(), trailers.size());
        if (rv != 0)
        {
            std::cerr << "nghttp3_conn_submit_trailers: " << nghttp3_strerror(rv)
                      << std::endl;
            return -1;
        }

        handler->shutdown_read(stream_id, NGHTTP3_H3_NO_ERROR);

        return 0;
    }

    int send_redirect_response(nghttp3_conn *httpconn,
                               unsigned int status_code,
                               const std::string &path)
    {
        return send_status_response(httpconn, status_code, {{"location", path}});
    }

    int64_t find_dyn_length(const std::string &path)
    {
        assert(path[0] == '/');

        uint64_t n = 0;

        for (auto it = std::begin(path) + 1; it != std::end(path); ++it)
        {
            if (*it < '0' || '9' < *it)
            {
                return -1;
            }
            auto d = *it - '0';
            if (n > (((1ull << 62) - 1) - d) / 10)
            {
                return -1;
            }
            n = n * 10 + d;
            if (n > handler->manager()->max_dyn_length)
            {
                return -1;
            }
        }

        return static_cast<int64_t>(n);
    }

    void http_acked_stream_data(size_t datalen)
    {
        if (!dynresp)
        {
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

template <class T, class TManager, class TSocket, class TBase>
class Http3Handler : public QuicServerHandlerT<T, TManager, TSocket, TBase>
{
    typedef QuicServerHandlerT<T, TManager, TSocket, TBase> Base;

public:
protected:
    nghttp3_conn *httpconn_;
    std::map<int64_t, std::unique_ptr<Stream<T>>> streams_;

public:
    int recv_stream_data(int64_t stream_id, uint8_t fin,
                                 const uint8_t *data, size_t datalen)
    { 
    // if (!config.quiet && !config.no_quic_dump) {
    //   debug::print_stream_data(stream_id, data, datalen);
    // }

        if (!httpconn_)
        {
            return 0;
        }

        auto nconsumed =
            nghttp3_conn_read_stream(httpconn_, stream_id, data, datalen, fin);
        if (nconsumed < 0)
        {
            std::cerr << "nghttp3_conn_read_stream: " << nghttp3_strerror(nconsumed)
                      << std::endl;
            return -1;
        }

        ngtcp2_conn_extend_max_stream_offset(this->conn_, stream_id, nconsumed);
        ngtcp2_conn_extend_max_offset(this->conn_, nconsumed);

        return nconsumed;
    }

    virtual int acked_stream_data_offset(int64_t stream_id, size_t datalen)
    {
        if (!httpconn_)
        {
            return 0;
        }

        auto rv = nghttp3_conn_add_ack_offset(httpconn_, stream_id, datalen);
        if (rv != 0)
        {
            std::cerr << "nghttp3_conn_add_ack_offset: " << nghttp3_strerror(rv)
                      << std::endl;
            return -1;
        }

        return 0;
    }

    virtual int on_stream_close(int64_t stream_id, uint64_t app_error_code)
    {
        if (IsDebug())
        {
            std::cerr << "QUIC stream " << stream_id << " closed" << std::endl;
        }

        if (httpconn_)
        {
            if (app_error_code == 0)
            {
                app_error_code = NGHTTP3_H3_NO_ERROR;
            }
            auto rv = nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
            switch (rv)
            {
            case 0:
                break;
            /*case NGHTTP3_ERR_STREAM_NOT_FOUND:
                if (ngtcp2_is_bidi_stream(stream_id))
                {
                    assert(!ngtcp2_conn_is_local_stream(conn_, stream_id));
                    ngtcp2_conn_extend_max_streams_bidi(conn_, 1);
                }
                break;*/
            default:
                std::cerr << "nghttp3_conn_close_stream: " << nghttp3_strerror(rv)
                          << std::endl;
                //last_error_ = quic_err_app(rv);
                return -1;
            }
        }

        return 0;
    }

    virtual void extend_max_remote_streams_bidi(uint64_t max_streams)
    {
        if (!httpconn_)
        {
            return;
        }

        nghttp3_conn_set_max_client_streams_bidi(httpconn_, max_streams);
    }

    virtual int extend_max_stream_data(int64_t stream_id, uint64_t max_data)
    {
        auto rv = nghttp3_conn_unblock_stream(httpconn_, stream_id);
        if (rv != 0)
        {
            std::cerr << "nghttp3_conn_unblock_stream: " << nghttp3_strerror(rv)
                      << std::endl;
            return -1;
        }
        return 0;
    }

    virtual int on_stream_reset(int64_t stream_id)
    {
        if (httpconn_)
        {
            auto rv = nghttp3_conn_reset_stream(httpconn_, stream_id);
            if (rv != 0)
            {
                std::cerr << "nghttp3_conn_reset_stream: " << nghttp3_strerror(rv)
                          << std::endl;
                return -1;
            }
        }
        return 0;
    }
};

} // namespace XSocket

#endif //_H_XHTTP3SERVER_IMPL_H_
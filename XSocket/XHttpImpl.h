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
#ifndef _H_XHTTP_IMPL_H_
#define _H_XHTTP_IMPL_H_

#include "XSocketImpl.h"
#include "http-parser/http_parser.h"
#if USE_WEBSOCKET
#include "XWebSocketImpl.h"
#endif//
#include "XStr.h"
#include "XCodec.h"
#include <sstream>
#include <strstream>

//chunk
//每个分块包含十六进制的长度值和数据，长度值独占一行，长度不包括它结尾的 CRLF（\r\n），也不包括分块数据结尾的 CRLF。
//最后一个分块长度值必须为 0，对应的分块数据没有内容，表示实体结束

namespace XSocket {

	class HttpUrl
	{
	protected:
		const char* url_;
		size_t len_;
		std::string hold_;
		struct http_parser_url parser_;
	public:
		HttpUrl(const char* url, size_t len, bool hold = false)
		{
			if(hold) {
				hold_.assign(url, len);
				url_ = hold_.c_str();
				len_ = hold_.size();
			} else {
				url_ = url;
				len_ = len;
			}
			//char *url = "http://www.baidu.com:8000/users?username=zhangsan#bar";
			http_parser_url_init(&parser_);
			int err = http_parser_parse_url(url_, len_, 0, &parser_);
			if(err == 0) {
			}
		}

		inline const char* data() { return url_; }
		inline size_t size() { return len_; }

		inline std::string Schema()
		{
			if(parser_.field_set & (1 << UF_SCHEMA)) {
				return std::string(url_ + parser_.field_data[UF_SCHEMA].off, parser_.field_data[UF_SCHEMA].len);
			}
			return std::string();
		}

		inline std::string Host()
		{
			if(parser_.field_set & (1 << UF_HOST)) {
				return std::string(url_ + parser_.field_data[UF_HOST].off, parser_.field_data[UF_HOST].len);
			}
			return std::string();
		}
		
		inline u_short Port()
		{
			u_short port = 80;
			if(parser_.port) {
				port = parser_.port;
			} else if(parser_.field_set & (1 << UF_SCHEMA)) {
				if(strnicmp(url_ + parser_.field_data[UF_SCHEMA].off, "https", parser_.field_data[UF_SCHEMA].len) == 0) {
					port = 443;
				}
			}
			return port;
		}
		
		inline std::string Path()
		{
			if(parser_.field_set & (1 << UF_PATH)) {
				return std::string(url_ + parser_.field_data[UF_PATH].off, parser_.field_data[UF_PATH].len);
			}
			return std::string();
		}
		
		inline std::string Query()
		{
			if(parser_.field_set & (1 << UF_QUERY)) {
				return std::string(url_ + parser_.field_data[UF_QUERY].off, parser_.field_data[UF_QUERY].len);
			}
			return std::string();
		}
		
		inline std::string Fragment()
		{
			if(parser_.field_set & (1 << UF_FRAGMENT)) {
				return std::string(url_ + parser_.field_data[UF_FRAGMENT].off, parser_.field_data[UF_FRAGMENT].len);
			}
			return std::string();
		}
		
		inline std::string UserInfo()
		{
			if(parser_.field_set & (1 << UF_USERINFO)) {
				return std::string(url_ + parser_.field_data[UF_USERINFO].off, parser_.field_data[UF_USERINFO].len);
			}
			return std::string();
		}
	};
	struct HttpHeader {
			HttpHeader() {}
			HttpHeader(const std::string& _name, const std::string& _value):name(_name),value(_value){}
			HttpHeader(std::string&& _name, std::string&& _value):name(std::move(_name)),value(std::move(_value)){}
			std::string name, value;
	};
	class HttpMessage
	{
	public:
		// %a 星期几的缩写
		// %A 星期几的全名 
		// %b 月份名称的缩写
		// %B 月份名称的全名
		// %c 本地端日期时间较佳表示字符串
		// %d 用数字表示本月的第几天 (范围为 00 至 31)日期 
		// %H 用 24 小时制数字表示小时数 (范围为 00 至 23)
		// %I 用 12 小时制数字表示小时数 (范围为 01 至 12) 
		// %j 以数字表示当年度的第几天 (范围为 001 至 366) 
		// %m 月份的数字 (范围由 1 至 12)
		// %M 分钟
		// %p 以 ''AM'' 或 ''PM'' 表示本地端时间
		// %S 秒数
		// %U 数字表示为本年度的第几周，第一个星期由第一个周日开始
		// %W 数字表示为本年度的第几周，第一个星期由第一个周一开始 
		// %w 用数字表示本周的第几天 ( 0 为周日)
		// %x 不含时间的日期表示法
		// %X 不含日期的时间表示法
		// %y 二位数字表示年份 (范围由 00 至 99)
		// %Y 完整的年份数字表示，即四位数
		// %Z(%z) 时区或名称缩写
		//Tue, 11 Feb 2020 04:23:47 GMT = %a, %d %b %Y %H:%M:%S GMT
		//time是本地时间
		//gmtime是格林尼治时间，会做时区转换，转换成0时区时间
		//localtime是本地时间，不会做时区转换，所以和gmtime互相转需要知道时区才能转换
		static inline std::time_t gm2localtime(const std::time_t& time, int tz = 8) {
			return time + tz * 60 *60;
			//return std::mktime(std::localtime(&time));
		}
		static inline std::time_t local2gmtime(const std::time_t& time, int tz = 8) {
			return gm2localtime(time, -tz);
			//return std::mktime(std::gmtime(&time));
		}
		static inline std::string tm2str(const std::tm* t, const char* format) {
#ifdef WIN32
			std::ostringstream ss;
			ss << std::put_time(t, format);
			return ss.str();
#else
			char buf[256] = {0};
			std::strftime(buf, 256, format, t);
			return buf;
#endif//
		}
		static inline std::tm str2tm(const char* time, const char* format) {
			std::tm t;
#ifdef WIN32
			std::istringstream ss(time);
			ss >> std::get_time(&t, format);
#else
			strptime(time, format, &t);
#endif
			return t;
		}
		static inline std::string gmtime2str(const std::time_t& time, const char* format) {
			return tm2str(std::gmtime(&time), format);
		}
		static inline std::time_t strgm2localtime(const char* time, const char* format) {
			std::tm t = str2tm(time,format);
			return gm2localtime(std::mktime(&t));
		}
		static inline std::string localtime2str(const std::time_t& time, const char* format) {
			return tm2str(std::localtime(&time), format);
		}
		static inline std::time_t strlocal2gmtime(const char* time, const char* format) {
			std::tm t = str2tm(time,format);
			return local2gmtime(std::mktime(&t));
		}
		static inline std::string httptime2str(const std::time_t& time = std::time(nullptr)) {
			return gmtime2str(time, "%a, %d %b %Y %H:%M:%S GMT");
		}
		static inline std::time_t str2httptime(const char* time) {
			return strgm2localtime(time, "%a, %d %h %Y %H:%M:%S GMT");
		}

		unsigned short http_major = 0;
		unsigned short http_minor = 0;
		std::vector<HttpHeader> fields_;
		std::string body_;
		
		unsigned short major() const { return http_major; }
		unsigned short minor() const { return http_minor; }
		void set_major(unsigned short major) { http_major = major; }
		void set_minor(unsigned short minor) { http_minor = minor; }

		inline const char* field(const char* name, size_t* len = nullptr) const {
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(stricmp(fields_[i].name.c_str(), name) == 0) {
					if(len) {
						*len = fields_[i].value.size();
					}
					return fields_[i].value.c_str();
				}
			}
			return nullptr;
		}
		inline void set_field(const std::string& name, const std::string& value)
		{
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(stricmp(fields_[i].name.c_str(), name.c_str()) == 0) {
					
					fields_[i].value = value;
					return;
				}
			}
			fields_.emplace_back(name,value);
		}
		inline void set_field(std::string&& name, std::string&& value)
		{
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(stricmp(fields_[i].name.c_str(), name.c_str()) == 0) {
					fields_[i].value = std::move(value);
					return;
				}
			}
			fields_.emplace_back(std::move(name),std::move(value));
		}
		inline void remove_field(std::string&& name)
		{
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(stricmp(fields_[i].name.c_str(), name.c_str()) == 0) {
					fields_.erase(fields_.begin() + i);
					return;
				}
			}
		}

		inline bool is_chunked() const {
			const char* transfer_encoding = field("transfer-encoding");
			if(transfer_encoding && stricmp("chunked", transfer_encoding) == 0) {
				return true;
			}
			return false;
		}
		inline void set_chunked(bool chunk = true) {
			if(chunk)
				set_field("transfer-encoding", "chunked");
			else
				remove_field("transfer-encoding");
		}

		inline const char* data() const { return body_.data(); }
		inline size_t size() const { return body_.size(); }
		inline void set_data(const std::string& body) { body_ = body; }
		inline void set_data(std::string&& body) { body_ = std::move(body); }
	};
	class HttpRequest : virtual public HttpMessage
	{
	public:
		unsigned int method_ = 0;
		std::string url_;

		inline unsigned int method() const { return method_; }
		inline void set_method(unsigned int method) { method_ = method; }
		
		inline const char* url(size_t* len = nullptr) const { 
			if(len) {
				*len = url_.size();
			}
			return url_.c_str();
		}
		inline void set_url(const std::string& url) { url_ = url; }

		std::string& to_string(std::string& buf) const
		{
			bool chunked = is_chunked();
			std::ostringstream oss;
			oss << http_method_str((enum http_method)method_) << " " << url_ << " HTTP/" << http_major << "." << http_minor << "\r\n";
			for(const auto& field : fields_)
			{
				oss << field.name << ": " << field.value << "\r\n";
			}
			oss << "\r\n";
			if(chunked) {
				oss << std::hex << body_.size() << "\r\n";
			} 
			oss << body_;
			if(chunked) {
				oss << "\r\n";
			}
			buf += oss.str();
			return buf;
		}
	};
	class HttpResponse : virtual public HttpMessage
	{
	public:
		int status_code = 0;
		std::string status_;
		
		inline int code() const { return status_code; }
		inline void set_code(unsigned int code) { status_code = code; }

		inline const char* reason(size_t* len = nullptr) const { 
			if(len) {
				*len = status_.size();
			}
			return status_.c_str();
		}
		inline void set_reason(const std::string& reason) { status_ = reason; }

		std::string& to_string(std::string& buf) const
		{
			bool chunked = is_chunked();
			std::ostringstream oss;
			oss << "HTTP/" << http_major << "." << http_minor << " " << status_code << " " << status_ << "\r\n";
			for(const auto& field : fields_)
			{
				oss << field.name << ": " << field.value << "\r\n";
			}
			oss << "\r\n";
			if(chunked) {
				oss << std::hex << body_.size() << "\r\n";
			}
			oss << body_;
			if(chunked) {
				oss << "\r\n";
			}
			buf += oss.str();
			return buf;
		}
	};

	template<class T>
	class HttpParserT
	{
		typedef HttpParserT<T> This;
	public:
	protected:
		http_parser_settings settings_ = {0};
		http_parser parser_ = {0};

		static int on_message_begin (http_parser* parser)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_message_begin();
			}
			return 0;
		}
		static int on_url(http_parser* parser, const char *at, size_t length)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_url(at,length);
			}
			return 0;
		}
		static int on_status(http_parser* parser, const char *at, size_t length)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_status(at,length);
			}
			return 0;
		}
		static int on_header_field(http_parser* parser, const char *at, size_t length)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_header_field(at,length);
			}
			return 0;
		}
		static int on_header_value(http_parser* parser, const char *at, size_t length)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_header_value(at,length);
			}
			return 0;
		}
		static int on_headers_complete (http_parser* parser)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_headers_complete();
			}
			return 0;
		}
		static int on_body(http_parser* parser, const char *at, size_t length)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_body(at,length);
			}
			return 0;
		}
		static int on_message_complete (http_parser* parser)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_message_complete();
			}
			return 0;
		}
		static int on_chunk_header (http_parser* parser)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_chunk_header();
			}
			return 0;
		}
		static int on_chunk_complete (http_parser* parser)
		{
			T* pT = (T*)parser->data;
			if(pT) {
				return pT->on_chunk_complete();
			}
			return 0;
		}

	public:	
		template<class TRequest>
		static bool is_response_needs_body(TRequest&& req, const HttpResponse& rsp)
		{
			int method = req.method();
			int code = rsp.code();
			return (code!= HTTP_STATUS_NO_CONTENT && code != HTTP_STATUS_NOT_MODIFIED && (code < 100 || code >= 200)
			 && method != HTTP_CONNECT && method != HTTP_HEAD);
		}

		/*
		 * the last message on the connection.
		 * If you are the server, respond with the "Connection: close" header.
		 * If you are the client, close the connection.
		 */
		template<class TMessage>
		static bool is_should_keep_alive(TMessage&& msg, int* timeout = nullptr)
		{
			const char* connection = msg.field("Connection");
			if(connection) {
				if (msg.major() > 0 && msg.minor() > 0) {
					/* HTTP/1.1 */
					if (stricmp(connection, "close") == 0) {
						return false;
					} else if (stricmp(connection, "timeout") == 0 && timeout) {
						*timeout = std::atoi(connection+8);
					}
				} else {
					/* HTTP/1.0 or earlier */
					if (stricmp(connection, "keep-alive") != 0) {
						return false;
					}
				}
			}
			return true;
		}

		HttpParserT(http_parser_type type = HTTP_BOTH)
		{
			settings_.on_message_begin = &This::on_message_begin;
			settings_.on_url = &This::on_url;
			settings_.on_status = &This::on_status;
			settings_.on_header_field = &This::on_header_field;
			settings_.on_header_value = &This::on_header_value;
			settings_.on_headers_complete = &This::on_headers_complete;
			settings_.on_body = &This::on_body;
			settings_.on_message_complete = &This::on_message_complete;
			settings_.on_chunk_header = &This::on_chunk_header;
			settings_.on_chunk_complete = &This::on_chunk_complete;
			http_parser_init(&parser_, type);
			parser_.data = static_cast<T*>(this);
		}

		//解析数据包
		int ParseBuf(const char* lpBuf, int & nBufLen) { 
			int nParsed = 0;
			ASSERT(!parser_.upgrade);
#if 0
			nParsed = http_parser_execute(&parser_, &settings_, lpBuf, nBufLen/2);
			nParsed += http_parser_execute(&parser_, &settings_, lpBuf + nBufLen/2, nBufLen - nBufLen/2);
#else
			nParsed = http_parser_execute(&parser_, &settings_, lpBuf, nBufLen);
#endif
			if(nParsed != nBufLen) {
				return SOCKET_PACKET_FLAG_NONE;
			}
			return SOCKET_PACKET_FLAG_COMPLETE;
		}

		inline void clear()
		{
			http_parser parser = parser_;
			http_parser_init(&parser_, (http_parser_type)parser_.type);
			//parser_.upgrade = parser.upgrade;
			parser_.data = parser.data;
		}

		inline bool upgrade() const { return parser_.upgrade; }
	};

	class HttpParser : public HttpParserT<HttpParser>
	{
		typedef HttpParserT<HttpParser> Base;
	public:
		typedef std::pair<const char*,size_t> strref;
		struct Message
		{
			unsigned short http_major = 0;
			unsigned short http_minor = 0;
			unsigned int method_ = 0;
			strref url_;
			unsigned short status_code = 0;
			strref status_;
			struct field {
				strref name, value;
			};
			std::vector<field> fields_;
			strref body_; 
			bool done_ = false;

			Message()
			{
				fields_.reserve(16);
			}

			inline bool is_done() { return done_; }

			inline void clear()
			{
				//清理之前的数据
				//url_ = strref();
				//status_ = strref();
				fields_.clear();
				//body_  = strref();
				done_ = false;
			}
 
			inline void zeroend()
			{
				if(url_.first) ((char*)url_.first)[url_.second] = 0;
				if(status_.first) ((char*)status_.first)[status_.second] = 0;
				for(auto field : fields_) {
					if(field.name.first) ((char*)field.name.first)[field.name.second] = 0;
					if(field.value.first) ((char*)field.value.first)[field.value.second] = 0;
				}
				if(body_.first) ((char*)body_.first)[body_.second] = 0;
			}

			inline unsigned short major() const { return http_major; }
			inline unsigned short minor() const { return http_minor; }
			inline unsigned int method() const { return method_; }
			
			inline const char* url(size_t* len = nullptr) const { 
				if(len) {
						*len = url_.second;
				}
				return url_.first;
			}
			
			inline int code() const { return status_code; }

			inline const char* reason(size_t* len = nullptr) const { 
				if(len) {
					*len = status_.second;
				}
				return status_.first;
			}

			inline const char* field(const char* name, size_t* len = nullptr) const {
				for(size_t i = 0; i < fields_.size(); i++)
				{
					if(strnicmp(fields_[i].name.first,name, fields_[i].name.second) == 0) {
						if(len) {
							*len = fields_[i].value.second;
						}
						return fields_[i].value.first;
					}
				}
				return nullptr;
			}

			inline const char* data() const { return body_.first; }
			inline size_t size() const { return body_.second; }

			void to_request(HttpRequest& req) const
			{
				req.set_major(major());
				req.set_minor(minor());
				req.set_method(method());
				req.set_url(url());
				for(const auto& field : fields_)
				{
					req.set_field(std::string(field.name.first,field.name.second), std::string(field.value.first,field.value.second));
				}
				req.set_data(std::string(data(),size()));
			}
			void to_response(HttpResponse& rsp) const
			{
				rsp.set_major(major());
				rsp.set_minor(minor());
				rsp.set_code(code());
				rsp.set_reason(reason());
				for(const auto& field : fields_)
				{
					rsp.set_field(std::string(field.name.first,field.name.second), std::string(field.value.first,field.value.second));
				}
				rsp.set_data(std::string(data(),size()));
			}
		};
	//protected:
		std::vector<Message> msgs_;

		inline Message& Msg(bool New = false) {
			if(New) {
				msgs_.resize(msgs_.size()+1);
			}
			return msgs_.back();
		}

		inline int on_message_begin() 
		{
			auto& msg = Msg(true);
			return 0;
		}
		
		inline int on_url(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.url_ = strref(at,length);
			return 0;
		}
		inline int on_status(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.status_ = strref(at,length);
			return 0;
		}
		inline int on_header_field(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.fields_.resize(msg.fields_.size()+1);
			msg.fields_.back().name = strref(at,length);
			return 0;
		}
		inline int on_header_value(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.fields_.back().value = strref(at,length);
			return 0;
		}
		inline int on_headers_complete ()
		{
			auto& msg = Msg();
			msg.http_major = parser_.http_major;
			msg.http_minor = parser_.http_minor;
			msg.method_ = parser_.method;
			msg.status_code = parser_.status_code;
			return 0;
		}
		inline int on_body(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.body_ = strref(at,length);
			return 0;
		}
		inline int on_message_complete ()
		{
			auto& msg = Msg();
			msg.done_ = true;
			return 0;
		}
		inline int on_chunk_header ()
		{
			return 0;
		}
		inline int on_chunk_complete ()
		{
			return 0;
		}
	public:
		HttpParser(http_parser_type type = HTTP_BOTH):Base(type) {
			msgs_.reserve(3);
		}

		//解析数据包
		int ParseBuf(const char* lpBuf, int & nBufLen) {
			int nParsed = 0;
			ASSERT(!parser_.upgrade);
			nParsed = http_parser_execute(&parser_, &settings_, lpBuf, nBufLen);
			if(nParsed < 0) {
				return SOCKET_PACKET_FLAG_NONE;
			}
			if(msgs_.empty() || !msgs_.back().is_done()) {
				clear(); //下次重新解析
				return SOCKET_PACKET_FLAG_PENDING;
			}
			for(auto& msg : msgs_) {
				msg.zeroend();
			}
			nBufLen = nParsed;
			return SOCKET_PACKET_FLAG_COMPLETE;
		}
		
		inline void clear()
		{
			Base::clear();
			msgs_.clear();
		}
		
		inline const std::vector<Message>& messages() { return msgs_; }
	};

	/*!
	 *	@brief HttpBuffer 定义.
	 *
	 *	封装HttpBuffer，实现Http数据包构建和解析
	 */
	template<class THolder>
	class HttpBufferT : public HttpParserT<HttpBufferT<THolder>>
	{
		typedef HttpBufferT<THolder> This;
		typedef HttpParserT<HttpBufferT<THolder>> Base;
	public:
		class Message : virtual public HttpRequest, virtual public HttpResponse
		{
		public:
			bool chunked_ = false;//对于chunk传输编码,body是当前chunk数据，最后的chunk是空
			bool chunk_done_ = false; //当前chunk是否传输完成
			bool done_ = false; //当前消息是否传输完成，如果是chunk是所有chunk是否都传输完成

			inline bool is_chunked() { return chunked_; }
			inline bool is_chunk_done() { return chunk_done_; }
			inline bool is_done() { return done_; }
		};
	//protected:
		THolder* holder_;
		std::shared_ptr<Message> msg_;

		inline Message& Msg(bool New = false) 
		{ 
			if(New) {
				msg_ = std::make_shared<Message>();
			}
			return *msg_;
		}

		inline int on_message_begin() 
		{
			auto& msg = Msg(true);
			return 0;
		}
		
		inline int on_url(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.url_.append(at,length);
			return 0;
		}
		inline int on_status(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.status_.append(at,length);
			return 0;
		}
		inline int on_header_field(const char *at, size_t length)
		{
			auto& msg = Msg();
			if(!msg.fields_.empty() && msg.fields_.back().value.empty()) {
				msg.fields_.back().name.append(at,length);
			} else {
				msg.fields_.resize(msg.fields_.size()+1);
				msg.fields_.back().name.assign(at,length);
			}
			return 0;
		}
		inline int on_header_value(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.fields_.back().value.append(at,length);
			return 0;
		}
		inline int on_headers_complete ()
		{
			auto& msg = Msg();
			msg.http_major = Base::parser_.http_major;
			msg.http_minor = Base::parser_.http_minor;
			msg.method_ = Base::parser_.method;
			msg.status_code = Base::parser_.status_code;
			return 0;
		}
		inline int on_body(const char *at, size_t length)
		{
			auto& msg = Msg();
			msg.body_.append(at,length);
			return 0;
		}
		inline int on_message_complete ()
		{
			auto& msg = Msg();
			msg.done_ = true;
			on_message();
			return 0;
		}
		inline int on_chunk_header ()
		{
			auto& msg = Msg();
			msg.chunked_ = true;
			msg.chunk_done_ = false;
			msg.body_.clear();
			return 0;
		}
		inline int on_chunk_complete ()
		{
			auto& msg = Msg();
			msg.chunk_done_ = true;
			if(!msg.body_.empty()) {
				on_message();
			}
			return 0;
		}

		inline void on_message ()
		{
			if(upgrade()) {
				//收到升级到WEBSOCKET消息
				holder_->OnUpgrade(msg_);
			} else {
				holder_->OnMessage(msg_);
			}
		}
		
	public:
		HttpBufferT(THolder* holder, http_parser_type type = HTTP_BOTH):Base(type),holder_(holder)
		{
		}

		void BuildReqBuf(std::string& buf, HttpRequest& req)
		{
			if(!req.major()) {
				req.set_major(holder_->GetHttpMajor());
				req.set_minor(holder_->GetHttpMinor());
			}
			req.remove_field("Proxy-Connection");

			/* Add the content length on a request if missing
			* Always add it for POST and PUT requests as clients expect it */
			if ((req.size() ||
				(req.method() == HTTP_POST || req.method() == HTTP_PUT)) &&
				!req.field("Content-Length")) {
				req.set_field("Content-Length", tostr(req.size()));
			}

			req.to_string(buf);
		}

		template<class T>
		void BuildRspBuf(std::string& buf, T&& req, HttpResponse& rsp)
		{
			if(!rsp.major()) {
				rsp.set_major(holder_->GetHttpMajor());
				rsp.set_minor(holder_->GetHttpMinor());
			}
			size_t reason_len = 0;rsp.reason(&reason_len);
			if(!reason_len) {
				rsp.set_reason(http_status_str((enum http_status)rsp.code()));
			}
			const char* connection = req.field("Connection");
			if (req.major() == 1) {
				if (req.minor() >= 1)
					rsp.set_field("Date", rsp.httptime2str());

				bool is_keepalive = false;
				if(connection && stricmp(connection,"keep-alive") == 0) {
					is_keepalive = true;
				}
				/*
				* if the protocol is 1.0; and the connection was keep-alive
				* we need to add a keep-alive header, too.
				*/
				if (req.minor() == 0 && is_keepalive)
					rsp.set_field("Connection", "keep-alive");
			}
			/*
			 * we need to add the content length if the
			 * user did not give it, this is required for
			 * persistent connections to work.
			 */
			/* Potentially add headers for unidentified content. */
			if (is_response_needs_body(req, rsp)) {
				bool chunked = rsp.is_chunked();
				if(!chunked) {
					if (!rsp.field("Content-Type")) {
						rsp.set_field("Content-Type", holder_->GetDefaultContentType());
					}
					if (!rsp.field("Content-Length")) {
						rsp.set_field("Content-Length", tostr(rsp.size()));
					}
				}
			}

			/* if the request asked for a close, we send a close, too */
			bool is_connection_close = false;
			const char* proxy_connection = req.field("Proxy-Connection");
			if (proxy_connection) {
				/* proxy connection */
				if(stricmp(proxy_connection, "keep-alive") != 0) {
					is_connection_close = true;
				}
			}
			if(connection) {
				if(stricmp(connection, "close") == 0) {
					is_connection_close = true;
				}
			} else {
				is_connection_close = true;
			}
			if(is_connection_close) {
				if(!proxy_connection)
					rsp.set_field("Connection", "close");
				rsp.remove_field("Proxy-Connection");
			}

			rsp.to_string(buf);
		}

		void BuildChunkBuf(std::string& buf, const char* lpBuf, int nBufLen)
		{
			std::ostringstream oss;
			oss << std::hex << nBufLen << "\r\n";
			std::string head = oss.str();
			size_t len = buf.size();
			buf.resize(len + head.size() + nBufLen + 2);
			memcpy(&buf[len], head.data(), head.size());
			if(lpBuf && nBufLen)
				memcpy(&buf[len + head.size()], lpBuf, nBufLen);
			memcpy(&buf[len + head.size() + nBufLen], "\r\n", 2);
		}

		inline void clear()
		{
			Base::clear();
			msg_.reset();
		}
	};

	/*!
	 *	@brief HttpSocketT 定义.
	 *
	 *	封装HttpSocketT，实现Http/Websocket收发数据功能
	 */
	template<class TBase>
	class HttpSocketT 
#if USE_WEBSOCKET
	: public WebSocketT<TBase>
#else
	: public TBase
#endif
	{
		typedef HttpSocketT<TBase> This;
#if USE_WEBSOCKET
		typedef WebSocketT<TBase> Base;
#else
		typedef TBase Base;
#endif
	protected:
		friend HttpBufferT<This>;
		typedef HttpBufferT<This> HttpBuffer;
		typedef typename HttpBuffer::Message Message;
		HttpBuffer http_buffer_;
		std::chrono::steady_clock::time_point close_if_time_point_; //等到时间点到达也关闭连接
	public:
		HttpSocketT(http_parser_type type = HTTP_BOTH):Base(),http_buffer_(this,type)
		{
		}

		~HttpSocketT() 
		{
			
		}

		inline int GetHttpMajor() { return 1; }
		inline int GetHttpMinor() { return 0; }
		inline int GetConnectionTimeout() { return 15; }
		inline const char* GetDefaultContentType() { return "text/html"; }

		template<class TRequest>
		inline void SendHttpRequest(TRequest&& req)
		{
			http_buffer_.BuildReqBuf(Base::SendBuf(), req);
			Base::SendBufDirect();
		}

		template<class TRequest>
		inline void SendHttpResponse(TRequest&& req, HttpResponse& rsp)
		{
			http_buffer_.BuildRspBuf(Base::SendBuf(), std::forward<TRequest>(req), rsp);
			Base::SendBufDirect();
		}

		inline void SendHttpChunk(const char* lpBuf, int nBufLen)
		{
			http_buffer_.BuildChunkBuf(Base::SendBuf(), lpBuf, nBufLen);
			Base::SendBufDirect();
		}

#if USE_WEBSOCKET
		//升级websocket
		void SendWSUpgrade(const char* host, const char* path = "/")
		{
			//Connection: Upgrade：表示要升级协议
			//Upgrade: websocket：表示要升级到 websocket 协议。
			//Sec-WebSocket-Version: 13：表示 websocket 的版本。如果服务端不支持该版本，需要返回一个Sec-WebSocket-Version包含服务端支持的版本号。
			//Sec-WebSocket-Key：与后面服务端响应首部的Sec-WebSocket-Accept是配套的，提供基本的防护，比如恶意的连接，或者无意的连接。
			char buf[1024] = {0};
			int buflen = sprintf(buf, "XSocket: %d", rand());
			char base64_key[1024] = {0};
#if USE_OPENSSL
			int base64_len = base64_encode(buf, buflen, base64_key, base64_len);
			if (base64_len < 0) {
				ASSERT(0);
				return;
			}
#else
			//int base64_len = Base64EncodeGetRequiredLength(buflen, BASE64_FLAG_NOCRLF);
			//Base64Encode((const byte*)buf, buflen, (char*)base64_key, &base64_len, BASE64_FLAG_NOCRLF);
			//base64_key[base64_len] = 0;
			en64((const byte*)buf, (byte*)base64_key, buflen);
#endif
			SendBuffer& send_buf = Base::SendBuf();int send_len = send_buf.size();
			send_buf.resize(send_len + 1024);
			std::ostrstream ss(&send_buf[send_len], 1024);
			ss << "GET " << path << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
			<< "Origin: http://" << host << "\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Version: 13\r\n"
			<< "Sec-WebSocket-Key: " << base64_key << "\r\n"
			<< "\r\n";
			send_buf.resize(send_len+ss.pcount());
			Base::SendBufDirect();
			//return str;
		}

		//接受升级websocket
		void SendAcceptWSUpgrade(const char* key, size_t key_len)
		{
			//Sec-WebSocket-Accept根据客户端请求首部的Sec-WebSocket-Key计算出来。
			//计算公式为：
			//将Sec-WebSocket-Key跟258EAFA5-E914-47DA-95CA-C5AB0DC85B11拼接。
			//通过 SHA1 计算出摘要，并转成 base64 字符串。
			char buf[1024] = {0};
			int buflen = sprintf(buf, "%.*s%s", key_len, key, WEBSOCKET_UUID);
			//std::string ws_key = std::string(key,key_len) + WEBSOCKET_UUID;
			SHA1_HASH hash_key = {0};
			SHA1(buf, buflen, &hash_key);
#if USE_OPENSSL
			int buflen = base64_encode((char*)hash_key.bytes, SHA1_HASH_SIZE, buf, buflen);
			if (buflen < 0) {
				ASSERT(0);
				return;
			}
#else
			//buflen = Base64EncodeGetRequiredLength(SHA1_HASH_SIZE, BASE64_FLAG_NOCRLF);
			//Base64Encode((const byte*)hash_key.bytes, SHA1_HASH_SIZE, (char*)buf, &buflen, BASE64_FLAG_NOCRLF);
			//buf[buflen] = 0;
			en64((const byte*)hash_key.bytes, (byte*)buf, SHA1_HASH_SIZE);
#endif
			SendBuffer& send_buf = Base::SendBuf();int send_len = send_buf.size();
			send_buf.resize(send_len + 1024);
			std::ostrstream ss(&send_buf[send_len], 1024);
			ss << "HTTP/1.1 101 Switching Protocols\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Accept: " << buf << "\r\n"
			<< "\r\n";
			//std::string str = ss.str();
			//int len = str.size();
			send_buf.resize(send_len+ss.pcount());
			Base::SendBufDirect();
			//return str;
		}
#endif//

	protected:
		//
		inline void StopCloseIfTimeOut() 
		{
			close_if_time_point_ = std::chrono::steady_clock::time_point();
		}

		inline void SetCloseIfTimeOut(size_t millis)
		{
			close_if_time_point_ = (std::chrono::steady_clock::now() + std::chrono::milliseconds(millis));
			Select(FD_IDLE);
		}

		inline int IsCloseIfTimeOut() {
			static const std::chrono::steady_clock::time_point tp_zero;
			if(close_if_time_point_ > tp_zero) {
				if(close_if_time_point_ < std::chrono::steady_clock::now()) {
					return 1;
				} else {
					return 2;
				}
			}
			return 0;
		 }

		inline void DoClose()
		{
			Base::Trigger(FD_CLOSE, 0); //关闭连接
		}

		inline bool IsUpgrade() { return http_buffer_.upgrade(); }

		//解析数据包
		virtual int ParseBuf(const char* lpBuf, int & nBufLen) {
			if(!IsUpgrade()) {
				int nFlags = http_buffer_.ParseBuf(lpBuf, nBufLen);
				return nFlags;
			} else {
#if USE_WEBSOCKET
				return Base::ParseBuf(lpBuf, nBufLen);
#endif
			}
			return SOCKET_PACKET_FLAG_COMPLETE;
		}

		virtual void OnUpgrade(const std::shared_ptr<Message>& msg)
		{
#if USE_WEBSOCKET
			//升级到了WebSocket，就不用超时关闭了，需要维持长连接
			if(IsCloseIfTimeOut()) {
				StopCloseIfTimeOut();
			}
			if(Base::IsConnectSocket()) {
				//收到接受升级到WEBSOCKET消息
			} else {
				//先接受升级到WEBSOCKET
				size_t len = 0;
				const char* key = msg->field("Sec-WebSocket-Key", &len);
				SendAcceptWSUpgrade(key, len);
			}
			//这里就完成了升级
#endif
		}

		virtual void OnMessage(const std::shared_ptr<Message>& msg)
		{
			
		}

// 	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags)
// 	{
// 		//PRINTF("%-79s", lpBuf);
// 		if (IsHttpParseUpgrade()) {
// #if USE_WEBSOCKET
// 			if(!IsWSParseDone()) {
// 				if(Base::IsConnectSocket()) {
// 					//收到接受升级到WEBSOCKET消息
// 					OnUpgrade();
// 				} else {
// 					//先接受升级到WEBSOCKET
// 					auto key = http_buffer_.GetField("Sec-WebSocket-Key");
// 					std::string buf = BuildAcceptUpgradeBuf(key.first, key.second);
// 					SendBuf(buf.c_str(), buf.size(), 0);
// 				}
// 				//这里就完成了升级
// 			} else {
// 				//说明收到了websocket数据
// 				auto body = http_buffer_.GetBody();
// 				int nFlags = SOCKET_PACKET_FLAG_COMPLETE;
// 				if(!IsWSParseFinal()) {
// 					DoParseCache(GetWSParseOPCode() != WS_OP_CONTINUE, false);
// 					nFlags |= SOCKET_PACKET_FLAG_CONTINUE; //分片
// 				} else {
// 					if(GetWSParseOPCode() == WS_OP_CONTINUE) {
// 						DoParseCache(false, true);
// 					}
// 					switch (GetWSParseOPCode())
// 					{
// 					case WS_OP_CLOSE:
// 						OnClose();
// 						break;
// 					case WS_OP_PING:
// 						OnPing();
// 						break;
// 					case WS_OP_PONG:
// 						OnPong();
// 						break;
// 					case WS_OP_TEXT:
// 						nFlags |= SOCKET_PACKET_FLAG_TEXT;
// 					default:
// 						OnMessage(body.first, body.second, nFlags);
// 						break;
// 					}
// 				}
// 			}
// #endif
// 		} else {
// 			OnMessage(http_buffer_);
// 		}
// 		Base::OnRecvBuf(lpBuf,nBufLen,nFlags);
// 	}

		virtual void OnRole(int nRole)
		{
			Base::OnRole(nRole);
			Base::SetLinger(0, 0); //保证数据发完，才关闭套接字
		}

		virtual void OnIdle()
		{
			auto isval = IsCloseIfTimeOut();
			if(isval) {
				if(isval == 1) {
					DoClose();
				} else {
					Select(FD_IDLE);
				}
			}
		}

		virtual void OnClose(int nErrorCode)
		{
			http_buffer_.clear();
			StopCloseIfTimeOut();

			Base::OnClose(nErrorCode);
		}
	};

	template<class T, class TBase>
	class HttpReqSocketImpl : public SocketExImpl<T,TBase>, public std::enable_shared_from_this<T>
	{
	public:
		typedef HttpReqSocketImpl<T, TBase> This;
		typedef SocketExImpl<T,TBase> Base;
	//protected:
		typedef typename Base::Message Message;
	public:
		struct RequestInfo {
			HttpRequest req_;
			std::function<void(std::shared_ptr<HttpResponse>)> rsp_;
			//std::promise<std::shared_ptr<HttpResponse>> rsp_;
		};
	protected:
		std::vector<std::shared_ptr<RequestInfo>> req_list_;
		size_t req_send_count_ = 0;
	public:
		HttpReqSocketImpl()
		{

		}
		~HttpReqSocketImpl() 
		{ 
		}

		void PostHttpRequest(std::shared_ptr<RequestInfo> req)
		{
			this_service()->Post(std::bind(&This::SendHttpRequest, shared_from_this(), req));
		}

		void SendHttpRequest(std::shared_ptr<RequestInfo> req)
		{
			if(!IsSocket()) {
				return;
			}
			req_list_.emplace_back(req);
			if(Base::IsConnected()) {
				if(!Base::IsSelect(FD_WRITE)) {
					InnerSendHttpRequest();
				}
			}
		}

	protected:
		//
		inline void InnerSendHttpRequest()
		{
			T* pT = static_cast<T*>(this);
			if(req_send_count_ < req_list_.size()) {
				do
				{
					auto& req_info = req_list_[req_send_count_++];
					Base::SendHttpRequest(req_info->req_);
				} while(req_send_count_ < req_list_.size());
				Base::SetCloseIfTimeOut(pT->GetConnectionTimeout()*1000);
			}
		}

		virtual void OnMessage(const std::shared_ptr<Message>& msg)
		{
			T* pT = static_cast<T*>(this);
			auto req_info = req_list_[0];
			std::shared_ptr<HttpResponse> rsp = std::static_pointer_cast<HttpResponse>(msg);
			try {
			req_info->rsp_(rsp);
			//req_info->rsp_.set_value(rsp);
			} catch(std::future_error err) {
				PRINTF("OnMessage %d %s", err.code(), err.what());
			} catch(...) {
				//
			}
			int timeout = pT->GetConnectionTimeout();
			if(msg->is_done()) {
				req_list_.erase(req_list_.begin());
				req_send_count_--;
				if(msg->is_done()) {
					if(!Base::http_buffer_.is_should_keep_alive(*rsp, &timeout)) {
						Base::DoClose();
						return;
					}
				} 
			}
			if(timeout) {
				SetCloseIfTimeOut(timeout*1000);
			}
		}
		
		virtual void OnConnect(int nErrorCode)
		{
			if(nErrorCode) {
				return Base::OnConnect(nErrorCode);
			} else {
				Base::OnConnect(nErrorCode);
				InnerSendHttpRequest();
			}
		}

		virtual void OnClose(int nErrorCode)
		{
			Base::OnClose(nErrorCode);

			T* pT = static_cast<T*>(this);
			if(!req_list_.empty()) {
				std::shared_ptr<HttpResponse> rsp = std::make_shared<HttpResponse>();
				rsp->set_major(pT->GetHttpMajor());
				rsp->set_minor(pT->GetHttpMinor());
				if(!nErrorCode) {
					nErrorCode = 
#ifdef WIN32
					WSAETIMEDOUT;
#else
					ETIMEDOUT;
#endif
				}
				rsp->set_code(nErrorCode);
				rsp->set_reason(GetErrorMessage(nErrorCode));
				for(size_t i = 0; i < req_list_.size(); i++)
				{
					auto req_info = req_list_[i];
					try {
						req_info->rsp_(rsp);
						//req_info->rsp_.set_value(rsp);
					} catch(std::future_error err) {
						PRINTF("OnClose %d %s", err.code(), err.what());
					} catch(...) {
						//
					}
				}
				req_list_.clear();
				req_send_count_ = 0;
			}
		}
	};
	
	template<class T, class TBase>
	class HttpsReqSocketImpl : public HttpReqSocketImpl<T,TBase>
	{
		typedef HttpReqSocketImpl<T,TBase> Base;
	public:
	protected:
		//
		virtual void OnSSLConnect()
		{
			Base::OnSSLConnect();
			InnerSendHttpRequest();
		}

		virtual void OnConnect(int nErrorCode)
		{
			Base::Base::OnConnect(nErrorCode);
		}
	};

	template<class T, class TBase>
	class HttpRspSocketImpl : public SocketExImpl<T,TBase>, public std::enable_shared_from_this<T>
	{
		typedef HttpRspSocketImpl<T,TBase> This;
		typedef SocketExImpl<T,TBase> Base;
	protected:
		typedef typename Base::Message Message;
	public:
		class HttpPath
		{
		public:
			std::string path_;
			std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)> cb_;
			std::set<HttpPath> sub_paths_;

			HttpPath() {}
			HttpPath(const std::string& path):path_(path)
			{

			}

			bool operator<(const HttpPath& o) const
			{
				return stricmp(path_.c_str(), o.path_.c_str()) < 0;
			}

			void operator()(std::shared_ptr<T> http, std::shared_ptr<HttpRequest> request) const
			{
				if(cb_) {
					cb_(http, request);
				}
			}

			HttpPath& Set(const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				cb_ = cb;
				return *this;
			}

			HttpPath& Path(const std::string& uri)
			{
				if(uri.empty() || uri == "/" || uri == "\\") {
					return *this;
				}
				return Sub(uri);
			}

			HttpPath& Sub(const std::string& uri) {
				std::string sub_uri;
				HttpPath* parent;
				HttpPath* path = Find(uri, &sub_uri, &parent);
				if(path) {
					return *path;
				} else {
					size_t pos = 0, offset = 0;
					do {
						pos = sub_uri.find_first_of("/\\",offset);
						std::string substr;
						if (pos !=string::npos) {
							substr = sub_uri.substr(offset,pos-offset);
						} else {
							substr = sub_uri.substr(offset);
						}
						if(!substr.empty()) {
							parent = (HttpPath*)&(*parent->sub_paths_.emplace(substr).first);
						}
						if(pos !=string::npos) {
							offset = pos + 1;
						} else {
							break;
						}
					} while(true);
					return *parent;
				}
			}

			HttpPath* Find(const std::string& uri, std::string* sub_uri = nullptr, HttpPath** parent = nullptr)
			{
				HttpPath* path = this;
				size_t pos = 0, offset = 0;
				do {
					pos = uri.find_first_of("/\\",offset);
					std::string substr;
					if (pos !=string::npos) {
						substr = uri.substr(offset,pos-offset);
					} else {
						substr = uri.substr(offset);
					}
					if(!substr.empty()) {
						auto it = path->sub_paths_.begin();
						for (; it != path->sub_paths_.end(); ++it)
						{
							if (it->path_ == substr) {
								break;
							}
						}
						if (it == path->sub_paths_.end()) {
							if(sub_uri) {
								*sub_uri = uri.substr(offset);
							}
							if (parent) {
								*parent = path;
							}
							return nullptr;
						} else {
							if (pos == string::npos) {
								if (parent) {
									*parent = path;
								}
								return (HttpPath*)&(*it);
							} else {
								path = (HttpPath*)&(*it);
							}
						}
					}
					if(pos !=string::npos) {
						offset = pos + 1;
					} else {
						break;
					}
				} while(true);
				return nullptr;
			}
		};
		class HttpRouter
		{
		protected:
			std::vector<HttpPath> roots_;
		public:
			HttpRouter():roots_(HTTP_SOURCE+1) {}

			inline HttpPath& ROOT(int method) { return roots_[method]; } 

			template<class TRequest>
			inline HttpPath* Find(TRequest&& req)
			{
				auto method = req.method();
				if(method < 0 || method > roots_.size()) {
					return nullptr;
				}
				return roots_[method].Find(req.url());
			}

			inline HttpPath& SET(int method, const std::string& uri, const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				return roots_[method].Path(uri).Set(cb);
			}

			inline HttpPath& GET(const std::string& uri, const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				return roots_[HTTP_GET].Path(uri).Set(cb);
			}

			inline HttpPath& POST(const std::string& uri, const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				return roots_[HTTP_POST].Path(uri).Set(cb);
			}

			inline void MATCH(std::initializer_list<size_t> list, std::string uri, const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				for (auto it = list.begin(); it != list.end(); ++it) {
					roots_[*it].Path(uri).Set(cb);
				}
			}

			inline void ANY(const std::string& uri, const std::function<void(std::shared_ptr<T>, std::shared_ptr<HttpRequest>)>& cb)
			{
				for(size_t i = 0; i < roots_.size(); i++)
				{
					roots_[i].Path(uri).Set(cb);
				}
			}
		};
	protected:
		std::queue<std::shared_ptr<HttpRequest>> req_list_;
		std::shared_ptr<HttpRequest> req_; //当前处理请求
		std::shared_ptr<HttpResponse> rsp_; //当前请求回应
		size_t close_if_send_size_ = 0;	//等待发送完指定size数据后，关闭连接
	public:
		static HttpRouter& Router() { static HttpRouter _router; return _router; }

		HttpRspSocketImpl()
		{
			Base::SetCloseIfTimeOut(3*1000);
		}
		~HttpRspSocketImpl() 
		{ 
		}

		inline void PostHttpResponse(std::shared_ptr<HttpResponse> rsp)
		{
			this_service()->Post(std::bind((void (This::*)(std::shared_ptr<HttpResponse>))&This::SendHttpResponse, shared_from_this(), rsp));
		}

		inline void PostHttpChunk(std::shared_ptr<std::string> rsp)
		{
			this_service()->Post(std::bind((void (This::*)(std::shared_ptr<std::string>))&This::SendHttpChunk, shared_from_this(), rsp));
		}

		inline void SendHttpResponse(std::shared_ptr<HttpResponse> rsp)
		{
			if(!IsSocket()) {
				return;
			}
			T* pT = static_cast<T*>(this);
			rsp_ = rsp;
			Base::SendHttpResponse(*req_, *rsp_);
			bool done = true;
			if(rsp_->is_chunked()) {
				if(rsp_->size()) {
					done = false;
				}
			}
			if(done) {
				pT->HandleHttpRequestDone();
				pT->HandleNextHttpRequest();
			}
		}

		inline void SendHttpChunk(std::shared_ptr<std::string> rsp)
		{
			if(!IsSocket()) {
				return;
			}
			T* pT = static_cast<T*>(this);
			if (!rsp_) {
				PRINTF("SendHttpChunk rsp");
			}
			if(rsp) {
				Base::SendHttpChunk(rsp->data(), rsp->size());
			} else {
				Base::SendHttpChunk(nullptr, 0);
				pT->HandleHttpRequestDone();
				pT->HandleNextHttpRequest();
			}
		}

	protected:
		//
		inline void HandleHttpRequestDone()
		{
			T* pT = static_cast<T*>(this);
			int timeout = pT->GetConnectionTimeout();
			if(!Base::http_buffer_.is_should_keep_alive(*rsp_, &timeout)) {
				close_if_send_size_ = Base::NotSendBufSize();
			} else {
				if(timeout) {
					Base::SetCloseIfTimeOut(timeout*1000);
				}
			}
			req_.reset();
			rsp_.reset();
		}

		inline void HandleNextHttpRequest()
		{
			if(!req_list_.empty()) {
				req_ = req_list_.front();
				req_list_.pop();
				HandleHttpRequest();
			}
		}

		inline void HandleHttpRequest()
		{
			auto handler = Router().Find(*req_);
			if(handler) {
				(*handler)(shared_from_this(), req_);
			} else {
				HttpResponse rsp;
				rsp.set_code(HTTP_STATUS_NOT_FOUND);
				Base::SendHttpResponse(*req_, rsp);
			}
		}
		
		virtual void OnMessage(const std::shared_ptr<Message>& msg)
		{
			T* pT = static_cast<T*>(this);
			Base::StopCloseIfTimeOut();
			if(!req_) {
				req_ = msg;
				pT->HandleHttpRequest();
			} else {
				req_list_.emplace(std::static_pointer_cast<HttpRequest>(msg));
			}
		}

		virtual void OnSendBuf(const char* lpBuf, int nBufLen)
		{
			Base::OnSendBuf(lpBuf, nBufLen);
			if(close_if_send_size_) {
				bool close_flag = close_if_send_size_ < nBufLen;
				if(!close_flag) {
					close_if_send_size_ -= nBufLen;
					close_flag = !close_if_send_size_;
				} else {
					close_if_send_size_ = 0;
				}
				if(close_flag) {
					Base::DoClose();
				}
			}
		}
	};
}

#endif//_H_XHTTP_IMPL_H_
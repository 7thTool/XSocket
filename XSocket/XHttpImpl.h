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
#ifdef USE_WEBSOCKET
#include "XWebSocketImpl.h"
#endif//
#include "XStr.h"
#include "XCodec.h"
#include <sstream>
#include <strstream>

namespace XSocket {

	class HttpMessage
	{
	public:
		unsigned short http_major = 0;
		unsigned short http_minor = 0;
		struct field {
			field(const std::string& _name, const std::string& _value):name(_name),value(_value){}
			field(std::string&& _name, std::string&& _value):name(std::move(_name)),value(std::move(_value)){}
			std::string name, value;
		};
		std::vector<field> fields_;
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
		inline void set_field(std::string& name, std::string& value)
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

		inline const char* data() const { body_.data(); }
		inline size_t size() const { return body_.size(); }
		inline void set_data(std::string& body) { body_ = body; }
		inline void set_data(std::string&& body) { body_ = std::move(body); }
	};
	class HttpRequest : public HttpMessage
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
		inline void set_url(std::string& url) { url_ = url; }

		void to_string(std::string& buf)
		{
			std::ostringstream oss;
			oss << http_method_str((enum http_method)method_) << " " << url_ << "HTTP/" << http_major << "." << http_minor << "\r\n";
			for(const auto& field : fields_)
			{
				oss << field.name << ": " << field.value << "\r\n";
			}
			oss << "\r\n";
			oss << body_;
			buf = oss.str();
		}
	};
	class HttpResponse : public HttpMessage
	{
	public:
		unsigned short status_code = 0;
		std::string status_;
		
		inline unsigned int code() const { return status_code; }
		inline void set_code(unsigned int code) { status_code = code; }

		inline const char* reason(size_t* len = nullptr) const { 
			if(len) {
				*len = status_.size();
			}
			return status_.c_str();
		}
		inline void set_reason(std::string& reason) { status_ = reason; }

		void to_string(std::string& buf)
		{
			std::ostringstream oss;
			oss << "HTTP/" << http_major << "." << http_minor << " " << status_code << " " << status_ << "\r\n";
			for(const auto& field : fields_)
			{
				oss << field.name << ": " << field.value << "\r\n";
			}
			oss << "\r\n";
			oss << body_;
			buf = oss.str();
		}
	};

	/*!
	 *	@brief HttpBuffer 定义.
	 *
	 *	封装HttpBuffer，实现Http数据包构建和解析
	 */
	template<class THolder>
	class HttpBufferT
	{
		typedef HttpBufferT<THolder> This;
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

			inline unsigned short major() const { return http_major; }
			inline unsigned short minor() const { return http_minor; }
			inline unsigned int method() const { return method_; }
			
			inline const char* url(size_t* len = nullptr) const { 
				if(len) {
						*len = url_.second;
				}
				return url_.first;
			}
			
			inline unsigned int code() const { return status_code; }

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

			void to_request(HttpRequest& req)
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
			void to_response(HttpResponse& rsp)
			{
				req.set_major(major());
				req.set_minor(minor());
				rsp.set_code(code());
				rsp.set_reason(reason());
				for(const auto& field : fields_)
				{
					rsp.set_field(std::string(field.name.first,field.name.second), std::string(field.value.first,field.value.second));
				}
				rsp.set_data(std::string(data(),size()));
			}
		};
	protected:
		THolder* holder_;
		http_parser_settings settings_ = {0};
		http_parser parser_ = {0};
		std::vector<Message> msgs_;

		inline void clear()
		{
			http_parser parser = parser_;
			http_parser_init(&parser_, (http_parser_type)parser_.type);
			parser_.upgrade = parser.upgrade;
			parser_.data = parser.data;
			msgs_.clear();
		}

		static int on_message_begin (http_parser* parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_message_begin();
			}
			return 0;
		}
		static int on_url(http_parser* parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_url(at,length);
			}
			return 0;
		}
		static int on_status(http_parser* parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_status(at,length);
			}
			return 0;
		}
		static int on_header_field(http_parser* parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_header_field(at,length);
			}
			return 0;
		}
		static int on_header_value(http_parser* parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_header_value(at,length);
			}
			return 0;
		}
		static int on_headers_complete (http_parser* parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_headers_complete();
			}
			return 0;
		}
		static int on_body(http_parser* parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_body(at,length);
			}
			return 0;
		}
		static int on_message_complete (http_parser* parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_message_complete();
			}
			return 0;
		}
		static int on_chunk_header (http_parser* parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_chunk_header();
			}
			return 0;
		}
		static int on_chunk_complete (http_parser* parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				return pThis->on_chunk_complete();
			}
			return 0;
		}
		
		inline int on_message_begin() 
		{
			msgs_.resize(msgs_.size()+1);
			return 0;
		}
		
		inline int on_url(const char *at, size_t length)
		{
			(char)at[length] = 0;
			msgs_.back().url_ = strref(at,length);
			return 0;
		}
		inline int on_status(const char *at, size_t length)
		{
			(char)at[length] = 0;
			msgs_.back().status_ = strref(at,length);
			return 0;
		}
		inline int on_header_field(const char *at, size_t length)
		{
			(char)at[length] = 0;
			auto& msg = msgs_.back();
			msg.fields_.resize(msg.fields_.size()+1);
			msg.fields_.back().name = strref(at,length);
			return 0;
		}
		inline int on_header_value(const char *at, size_t length)
		{
			(char)at[length] = 0;
			msgs_.back().fields_.back().value = strref(at,length);
			return 0;
		}
		inline int on_headers_complete ()
		{
			return 0;
		}
		inline int on_body(const char *at, size_t length)
		{
			msgs_.back().body_ = strref(at,length);
			return 0;
		}
		inline int on_message_complete ()
		{
			auto& msg = msgs_.back();
			msg.http_major = parser_.http_major;
			msg.http_minor = parser_.http_minor;
			msg.method_ = parser_.method;
			msg.status_code = parser_.status_code;
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

		template<class T>
		static bool is_response_needs_body(T&& req)
		{
			int code = req.code();
			int method = req.method();
			return (code!= HTTP_STATUS_NO_CONTENT && code != HTTP_STATUS_NOT_MODIFIED && (code < 100 || code >= 200)
			 && method != HTTP_CONNECT && method != HTTP_HEAD);
		}

	public:
		HttpBufferT(THolder* holder, http_parser_type type = HTTP_BOTH):holder_(holder)
		{
			msgs_.reserve(3);

			settings_.on_message_begin = &This::on_message_begin;
			settings_.on_url = &This::on_url;
			settings_.on_status = &This::on_status;
			settings_.on_header_field = &This::on_header_field;
			settings_.on_header_value = &This::on_header_value;
			settings_.on_body = &This::on_body;
			settings_.on_message_complete = &This::on_message_complete;
			http_parser_init(&parser_, type);
			parser_.data = this;
		}

		/*
		 * the last message on the connection.
		 * If you are the server, respond with the "Connection: close" header.
		 * If you are the client, close the connection.
		 */
		template<class T>
		static bool is_should_keep_alive(T&& msg)
		{
			const char* connection = msg.field("Connection");
			if(connection) {
				if (msg.major() > 0 && msg.minor() > 0) {
					/* HTTP/1.1 */
					if (stricmp(connection, "close") == 0) {
						return false;
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

		static void BuildReqBuf(std::string& buf, HttpRequest& req)
		{
			if(req.major()) {
				req.set_major(1);
				req.set_minor(0);
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
		static void BuildRspBuf(std::string& buf, T&& req, HttpResponse& rsp)
		{
			if(!rsp.major()) {
				rsp.set_major(req.major());
				rsp.set_minor(req.minor());
			}
			if (req.major() == 1) {
				if (req.minor() >= 1)
					rsp.set_field("Date", gmt_time_now());

				bool is_keepalive = stricmp(req.field("Connection"),"keep-alive") == 0;
				/*
				* if the protocol is 1.0; and the connection was keep-alive
				* we need to add a keep-alive header, too.
				*/
				if (req.minor() == 0 && is_keepalive)
					rsp.set_field("Connection", "keep-alive");

				if ((req.minor() >= 1 || is_keepalive) && is_response_needs_body(req)) {
					/*
					* we need to add the content length if the
					* user did not give it, this is required for
					* persistent connections to work.
					*/
					if (!rsp.field("Transfer-Encoding") && !rsp.field("Content-Length")) {
						rsp.set_field("Content-Length", tostr(rsp.size()));
					}
				}
			}
				
			/* Potentially add headers for unidentified content. */
			if (is_response_needs_body(req)) {
				if (!rsp.field("Content-Type")) {
					rsp.set_field("Content-Type", "text/html");
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
			const char* connection = req.field("Connection");
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
			nBufLen = nParsed;
			for(const auto& msg : msgs_) {
				if(upgrade()) {
					//收到升级到WEBSOCKET消息
					holder_->OnUpgrade(msg);
				} else {
					holder_->OnMessage(msg);
				}
			}
			clear();
			return SOCKET_PACKET_FLAG_COMPLETE;
		}

		inline bool upgrade() const { return parser_.upgrade; }
	};

	/*!
	 *	@brief HttpSocketT 定义.
	 *
	 *	封装HttpSocketT，实现Http/Websocket收发数据功能
	 */
	template<class TBase>
	class HttpSocketT 
#ifdef USE_WEBSOCKET
	: public WebSocketT<TBase>
#else
	: public TBase
#endif
	{
		typedef HttpSocketT<TBase> This;
#ifdef USE_WEBSOCKET
		typedef WebSocketT<TBase> Base;
#else
		typedef TBase Base;
#endif
	protected:
		typedef HttpBufferT<This> HttpBuffer;
		typedef typename HttpBuffer::Message HttpBufferMessage;
		friend class  HttpBuffer;
		HttpBuffer http_buffer_;
		size_t close_if_send_size_ = 0;	//等待发送完指定size数据后，关闭连接
		std::chrono::steady_clock::time_point close_if_time_point_; //等到时间点到达也关闭连接
	public:
		HttpSocketT(http_parser_type type = HTTP_BOTH):Base(),http_buffer_(this,type)
		,close_if_time_point_(std::chrono::steady_clock::now() + std::chrono::milliseconds(15000))
		{
			Select(FD_IDLE);
		}

		~HttpSocketT() 
		{
			
		}

		void SendHttpReqBuf(HttpRequest& msg)
		{
			http_buffer_.BuildReqBuf(Base::SendBuf(), msg);
			Base::SendBufDirect();
			if(!http_buffer_.is_should_keep_alive(msg)) {
				close_if_send_size_ = Base::NotSendBufSize();
				close_if_time_point_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
				if(!Base::IsSelect(FD_IDLE)) {
					Base::Select(FD_IDLE);
				}
			}
		}

		template<class T>
		void SendHttpRspBuf(T&& req, HttpResponse& msg)
		{
			http_buffer_.BuildRspBuf(Base::SendBuf(), std::forward<T>(req), msg);
			Base::SendBufDirect();
			if(!http_buffer_.is_should_keep_alive(msg)) {
				close_if_send_size_ = Base::NotSendBufSize();
				close_if_time_point_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
				if(!Base::IsSelect(FD_IDLE)) {
					Base::Select(FD_IDLE);
				}
			}
		}

#ifdef USE_WEBSOCKET
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
			int base64_len = Base64EncodeGetRequiredLength(buflen, BASE64_FLAG_NOCRLF);
			Base64Encode((const byte*)buf, buflen, (char*)base64_key, &base64_len, BASE64_FLAG_NOCRLF);
			base64_key[base64_len] = 0; 
			std::string& send_buf = Base::SendBuf();int send_len = send_buf.size();
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
			buflen = Base64EncodeGetRequiredLength(SHA1_HASH_SIZE, BASE64_FLAG_NOCRLF);
			Base64Encode((const byte*)hash_key.bytes, SHA1_HASH_SIZE, (char*)buf, &buflen, BASE64_FLAG_NOCRLF);
			buf[buflen] = 0; 
			std::string& send_buf = Base::SendBuf();int send_len = send_buf.size();
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
		//解析数据包
		virtual int ParseBuf(const char* lpBuf, int & nBufLen) {
			if(!http_buffer_.upgrade()) {
				int nFlags = http_buffer_.ParseBuf(lpBuf, nBufLen);
				return nFlags;
			} else {
#ifdef USE_WEBSOCKET
				return Base::ParseBuf(lpBuf, nBufLen);
#endif
			}
			return SOCKET_PACKET_FLAG_COMPLETE;
		}

		virtual void OnUpgrade(const HttpBufferMessage& msg)
		{
#ifdef USE_WEBSOCKET
			if(Base::IsConnectSocket()) {
				//收到接受升级到WEBSOCKET消息
			} else {
				//先接受升级到WEBSOCKET
				size_t len = 0;
				const char* key = msg.field("Sec-WebSocket-Key", &len);
				SendAcceptWSUpgrade(key, len);
			}
			//这里就完成了升级
#endif
		}

		virtual void OnMessage(const HttpBufferMessage& msg)
		{
			
		}

		virtual void OnIdle()
		{
			//if(close_if_send_size_) {
				if(close_if_time_point_ < std::chrono::steady_clock::now()) {
					Base::Trigger(FD_CLOSE, 0); //关闭连接
				}
			//}
		}

// 	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags)
// 	{
// 		//PRINTF("%-79s", lpBuf);
// 		if (IsHttpParseUpgrade()) {
// #ifdef USE_WEBSOCKET
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
					Base::Trigger(FD_CLOSE, 0); //关闭连接
				}
			}
		}
	};

}

#endif//_H_XHTTP_IMPL_H_
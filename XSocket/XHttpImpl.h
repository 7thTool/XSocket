/*
* Copyright: 7thTool Open Source (i7thTool@qq.com)
*
* Version	: 1.1.1
* Author	: Scott
* Project	: http://git.oschina.net/7thTool/XSocket
* Blog		: http://blog.csdn.net/zhangzq86
*
* LICENSED UNDER THE GNU LESSER GENERAL PUBLIC LICENSE, VERSION 2.1 (THE "LICENSE");
* YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
* UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
* DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
* SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
* LIMITATIONS UNDER THE LICENSE.
*/

#ifndef _H_XHTTP_IMPL_H_
#define _H_XHTTP_IMPL_H_

#include "XSocketImpl.h"
#include "http-parser/http_parser.h"
#ifdef USE_WEBSOCKET
//#include "ws-parser/ws_parser.h" //测试未通过
#include "websocket-parser/websocket_parser.h" //这个可以解析和构建ws数据包
#endif//
#include "XCodec.h"
#include <sstream>
#include <strstream>

namespace XSocket {

	typedef std::pair<const char*,size_t> strref;
	class HttpRequest
	{
	public:
		strref url_;
		strref status_;
		struct http_header {
			strref name, value;
		};
		std::vector<http_header> fields_;
		strref body_;

		HttpRequest() {
			fields_.reserve(16);
		}
		
		inline strref GetFieldValue(const char* name) {
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(strncmp(fields_[i].name.first,name, fields_[i].name.second) == 0) {
					return fields_[i].value;
				}
			}
			return strref();
		}

		inline strref GetBody() { return body_; }
	};

/*!
 *	@brief HttpSocketT 定义.
 *
 *	封装HttpSocketT，实现Http/Websocket收发数据功能
 */
template<class TBase>
class HttpSocketT : public TBase
{
	typedef HttpSocketT<TBase> This;
	typedef TBase Base;
public:
	HttpSocketT(http_parser_type type = HTTP_BOTH)
	{
			settings_.on_message_begin = &This::on_message_begin;
			settings_.on_url = &This::on_url;
			settings_.on_status = &This::on_status;
			settings_.on_header_field = &This::on_header_field;
			settings_.on_header_value = &This::on_header_value;
			settings_.on_body = &This::on_body;
			settings_.on_message_complete = &This::on_message_complete;
			http_parser_init(&parser_, type);
			parser_.data = this;
#ifdef USE_WEBSOCKET
			// ws_settings_.on_data_begin = &This::on_data_begin;
			// ws_settings_.on_data_payload = &This::on_data_payload;
			// ws_settings_.on_data_end = &This::on_data_end;
			// ws_settings_.on_control_begin = &This::on_control_begin;
			// ws_settings_.on_control_payload = &This::on_control_payload;
			// ws_settings_.on_control_end = &This::on_control_end;
			websocket_parser_settings_init(&ws_settings_);
			ws_settings_.on_frame_header = &This::on_frame_header;
			ws_settings_.on_frame_body = &This::on_frame_body;
			ws_settings_.on_frame_end = &This::on_frame_end;
			websocket_parser_init(&ws_parser_);
			// Attention! Sets your <data> after websocket_parser_init
			ws_parser_.data = this;
#endif
	}

	~HttpSocketT() 
	{
		
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen) { 
		int nParsed = 0;
			if(!IsUpgrade()) {
				done_ = 0;
				nParsed = http_parser_execute(&parser_, &settings_, lpBuf, nBufLen);
				if(nParsed < 0) {
					//出错
					done_ = nParsed;
				} else if(!IsDone()) {
					return SOCKET_PACKET_FLAG_PENDING;
				} else {
					nBufLen = nParsed;
					done_ = nParsed;
				}
			} else {
#ifdef USE_WEBSOCKET
				ws_done_ = 0;
				//nParsed = ws_parser_execute(&ws_parser_, &ws_settings_, this, (char*)lpBuf, nBufLen);
				nParsed = websocket_parser_execute(&ws_parser_, &ws_settings_, lpBuf, nBufLen);
				if(nParsed < 0) {
					//出错
					ws_done_ = nParsed;
				} else if(!IsWSDone()) {
					return SOCKET_PACKET_FLAG_PENDING;
				} else {
					//nParsed = nBufLen - ws_parser_.bytes_remaining;
					nBufLen = nParsed;
					ws_done_ = nParsed;
				}
#endif
			}
			return SOCKET_PACKET_FLAG_COMPLETE;
	}

	virtual void OnMessage(const HttpRequest& req)
	{

	}

#ifdef USE_WEBSOCKET
	virtual void OnUpgrade()
	{

	}
	virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
	{

	}
	virtual void OnWSClose()
	{
		Base::Trigger(FD_CLOSE, 0);
	}
	virtual void OnWSPing()
	{
		//Pong();
	}
	virtual void OnWSPong()
	{
		//
	}
#endif

// 	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags)
// 	{
// 		//PRINTF("%-79s\n", lpBuf);
// 		if (IsUpgrade()) {
// #ifdef USE_WEBSOCKET
// 			if(!IsWSDone()) {
// 				if(Base::IsConnectSocket()) {
// 					//收到接受升级到WEBSOCKET消息
// 					OnUpgrade();
// 				} else {
// 					//先接受升级到WEBSOCKET
// 					auto key = request_.GetFieldValue("Sec-WebSocket-Key");
// 					std::string buf = BuildAcceptUpgradeBuf(key.first, key.second);
// 					SendBuf(buf.c_str(), buf.size(), 0);
// 				}
// 				//这里就完成了升级
// 			} else {
// 				//说明收到了websocket数据
// 				auto body = request_.GetBody();
// 				int nFlags = SOCKET_PACKET_FLAG_COMPLETE;
// 				if(!IsWSFinal()) {
// 					Cache(GetOPCode() != WS_OP_CONTINUE, false);
// 					nFlags |= SOCKET_PACKET_FLAG_CONTINUE; //分片
// 				} else {
// 					if(GetOPCode() == WS_OP_CONTINUE) {
// 						Cache(false, true);
// 					}
// 					switch (GetOPCode())
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
// 			OnMessage(request_);
// 		}
// 		Base::OnRecvBuf(lpBuf,nBufLen,nFlags);
// 	}

// 	virtual void OnSendBuf(const char* lpBuf, int nBufLen)
// 	{
// 		Base::OnSendBuf(lpBuf, nBufLen);
// 	}

protected:
		http_parser_settings settings_ = {0};
		http_parser parser_ = {0};
		HttpRequest request_;
		int done_ = 0;

		inline bool IsUpgrade() { return parser_.upgrade; }
		inline bool IsError() { return done_ < 0; }
		inline bool IsDone() { return done_ != 0; }

#ifdef USE_WEBSOCKET
		// ws_parser_callbacks_t ws_settings_;
		// ws_parser_t ws_parser_;
		// ws_frame_type_t ws_type_;
		websocket_parser_settings ws_settings_;
		websocket_parser ws_parser_;
		uint8_t ws_flags_ = 0; //分片时Cache标志
		std::string ws_body_;//分片时Cache数据
		int ws_done_ = 0;
		//inline ws_frame_type_t GetWSType() { return ws_type_; }
		inline int GetOPCode() { return ws_parser_.flags & WS_OP_MASK; }
		inline bool	IsWSFinal() { return ws_parser_.flags & WS_FIN; }
		inline bool IsWSError() { return ws_done_ < 0; }
		inline bool IsWSDone() { return ws_done_ != 0; }
		inline void ClearCache() { 
			ws_flags_ = 0;
			ws_body_.clear();
		}
		inline void Cache(bool first, bool end) { 
			if(first) {
				ClearCache();
				ws_flags_ = ws_parser_.flags;
			}
			ws_body_.append(request_.body_.first,request_.body_.second); 
			if(end) {
				ws_flags_ |= WS_FIN;
				ws_parser_.flags |= ws_flags_;
				request_.body_ = strref(ws_body_.c_str(),ws_body_.size());
			}
		}
#endif

#ifdef USE_WEBSOCKET
		//升级websocket
		void Upgrade(const char* host, const char* path = "/")
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
			std::ostrstream ss(Base::SendBuf(1024), 1024);
			ss << "GET " << path << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
			<< "Origin: http://" << host << "\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Version: 13\r\n"
			<< "Sec-WebSocket-Key: " << base64_key << "\r\n"
			<< "\r\n";
			//std::string str = ss.str();
			//int len = str.size();
			Base::SendBufDirect(1024-ss.pcount());
			//return str;
		}

		//接受升级websocket
		void AcceptUpgrade(const char* key, size_t key_len)
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
			std::ostrstream ss(Base::SendBuf(1024), 1024);
			ss << "HTTP/1.1 101 Switching Protocols\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Accept: " << buf << "\r\n"
			<< "\r\n";
			//std::string str = ss.str();
			//int len = str.size();
			Base::SendBufDirect(1024-ss.pcount());
			//return str;
		}

		void SendWebSocketBuf(const char* body, int body_len, int flags = WS_OP_TEXT|WS_FINAL_FRAME, uint32_t mask = 0)
		{
			if(mask) {
				mask = htonl(mask);
				flags |= WS_HAS_MASK;
			}
			size_t frame_len = websocket_calc_frame_size(flags, body_len);
			websocket_build_frame((char*)Base::SendBuf(frame_len), flags, (char*)&mask, body, body_len);
			Base::SendBufDirect(0);
		}
#endif//
		
	protected:
		//
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
			return 0;
		}
		
		inline int on_url(const char *at, size_t length)
		{
			request_.url_ = strref(at,length);
			return 0;
		}
		inline int on_status(const char *at, size_t length)
		{
			request_.status_ = strref(at,length);
			return 0;
		}
		inline int on_header_field(const char *at, size_t length)
		{
			request_.fields_.resize(request_.fields_.size()+1);
			request_.fields_.back().name = strref(at,length);
			return 0;
		}
		inline int on_header_value(const char *at, size_t length)
		{
			request_.fields_.back().value = strref(at,length);
			return 0;
		}
		inline int on_headers_complete ()
		{
			return 0;
		}
		inline int on_body(const char *at, size_t length)
		{
			request_.body_ = strref(at,length);
			return 0;
		}
		inline int on_message_complete ()
		{
			done_ = true;
			//
			if (IsUpgrade()) {
#ifdef USE_WEBSOCKET
				if(Base::IsConnectSocket()) {
					//收到接受升级到WEBSOCKET消息
					OnUpgrade();
				} else {
					//先接受升级到WEBSOCKET
					auto key = request_.GetFieldValue("Sec-WebSocket-Key");
					AcceptUpgrade(key.first, key.second);
				}
				//这里就完成了升级
#endif
			} else {
				OnMessage(request_);
			}
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

#ifdef USE_WEBSOCKET
		// static int on_data_begin(void* data, ws_frame_type_t type)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_begin(type);
		// 	}
		// 	return 0;
		// }
		
		// static int on_data_payload(void* data, const char* at, size_t length)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_payload(at, length);
		// 	}
		// 	return 0;
		// }
		
		// static int on_data_end(void* data)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_end();
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_begin(void* data, ws_frame_type_t type)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_control_begin(type);
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_payload(void* data, const char* at, size_t length)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_control_payload(at, length);
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_end(void* data)
		// {
		// 	This* pThis = (This*)data;
		// 	if(pThis) {
		// 		return pThis->on_control_end();
		// 	}
		// 	return 0;
		// }

		// inline int on_data_begin(ws_frame_type_t type)
		// {
		// 	ws_type_ = type;
		// 	return 0;
		// }
		
		// inline int on_data_payload(const char* at, size_t length)
		// {
		// 	body_ = strref(at,length);
		// 	return 0;
		// }
		
		// inline int on_data_end()
		// {
		// 	ws_done_ = true;
		// 	return 0;
		// }
		
		// inline int on_control_begin(ws_frame_type_t type)
		// {
		// 	ws_type_ = type;
		// 	return 0;
		// }
		
		// inline int on_control_payload(const char* at, size_t length)
		// {
		// 	body_ = strref(at,length);
		// 	return 0;
		// }
		
		// inline int on_control_end()
		// {
		// 	ws_done_ = true;
		// 	return 0;
		// }
		
		static int on_frame_header(websocket_parser *parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				pThis->on_frame_header();
			}
			return 0;
		}

		static int on_frame_body(websocket_parser *parser, const char *at, size_t length)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				pThis->on_frame_body(at,length);
			}
			return 0;
		}

		static int on_frame_end(websocket_parser *parser)
		{
			This* pThis = (This*)parser->data;
			if(pThis) {
				pThis->on_frame_end();
			}
			return 0;
		}

		inline int on_frame_header()
		{
			if (ws_parser_.length) {
				// body_ = strref();
				// decode_body_.clear();
				// if (ws_parser_.flags & WS_HAS_MASK) {
				// 	decode_body_.resize(ws_parser_.length); // allocate memory for frame body, if body exists
				// }
			}
			return 0;
		}

		inline int on_frame_body(const char *at, size_t length)
		{
			if (ws_parser_.flags & WS_HAS_MASK) {
				// if frame has mask, we have to copy and decode data via websocket_parser_copy_masked function
				//websocket_parser_decode(&decode_body_[ws_parser_.offset], at, length, &ws_parser_);
				websocket_parser_decode((char*)at, at, length, &ws_parser_);
			}
			request_.body_ = strref(at,length);
			return 0;
		}

		inline int on_frame_end()
		{
			ws_done_ = true;
			//
				int nFlags = SOCKET_PACKET_FLAG_COMPLETE;
				if(!IsWSFinal()) {
					Cache(GetOPCode() != WS_OP_CONTINUE, false);
					nFlags |= SOCKET_PACKET_FLAG_CONTINUE; //分片
				} else {
					if(GetOPCode() == WS_OP_CONTINUE) {
						Cache(false, true);
					}
					auto body = request_.GetBody();
					switch (GetOPCode())
					{
					case WS_OP_CLOSE:
						OnWSClose();
						break;
					case WS_OP_PING:
						OnWSPing();
						break;
					case WS_OP_PONG:
						OnWSPong();
						break;
					case WS_OP_TEXT:
						nFlags |= SOCKET_PACKET_FLAG_TEXT;
					default:
						OnWSMessage(body.first, body.second, nFlags);
						break;
					}
				}
			return 0;
		}
#endif
};

}

#endif//_H_XHTTP_IMPL_H_
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

#ifndef _H_XHTTP_PARSER_H_
#define _H_XHTTP_PARSER_H_

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

/*!
 *	@brief XHttpParser 定义.
 *
 *	封装XHttpParser，实现收发数据解析功能
 */
	class XHttpParser
	{
	public:
		http_parser_settings settings_ = {0};
		http_parser parser_ = {0};
		typedef std::pair<const char*,size_t> strref;
		strref url_;
		strref status_;
		struct http_header {
			strref name, value;
		};
		std::vector<http_header> fields_;
		strref body_;
		int done_ = 0;

		inline bool IsUpgrade() { return parser_.upgrade; }
		inline bool IsError() { return done_ < 0; }
		inline bool IsDone() { return done_ != 0; }

		inline strref GetFieldValue(const char* name) {
			for(size_t i = 0; i < fields_.size(); i++)
			{
				if(strncmp(fields_[i].name.first,name, fields_[i].name.second) == 0) {
					return fields_[i].value;
				}
			}
			return strref();
		}

#ifdef USE_WEBSOCKET
		// ws_parser_callbacks_t ws_settings_;
		// ws_parser_t ws_parser_;
		// ws_frame_type_t ws_type_;
		websocket_parser_settings ws_settings_;
		websocket_parser ws_parser_;
		int ws_done_ = 0;
		//inline ws_frame_type_t GetWSType() { return ws_type_; }
		inline int GetOPCode() { return ws_parser_.flags & WS_OP_MASK; }
		inline bool	IsWSFinal() { return ws_parser_.flags & WS_FIN; }
		inline bool IsWSError() { return ws_done_ < 0; }
		inline bool IsWSDone() { return ws_done_ != 0; }
#endif
		inline strref GetBody() { return body_; }

		XHttpParser(http_parser_type type = HTTP_REQUEST)
		{
			settings_.on_message_begin = &XHttpParser::on_message_begin;
			settings_.on_url = &XHttpParser::on_url;
			settings_.on_status = &XHttpParser::on_status;
			settings_.on_header_field = &XHttpParser::on_header_field;
			settings_.on_header_value = &XHttpParser::on_header_value;
			settings_.on_body = &XHttpParser::on_body;
			settings_.on_message_complete = &XHttpParser::on_message_complete;
			http_parser_init(&parser_, type);
			parser_.data = this;
			fields_.reserve(16);
#ifdef USE_WEBSOCKET
			// ws_settings_.on_data_begin = &XHttpParser::on_data_begin;
			// ws_settings_.on_data_payload = &XHttpParser::on_data_payload;
			// ws_settings_.on_data_end = &XHttpParser::on_data_end;
			// ws_settings_.on_control_begin = &XHttpParser::on_control_begin;
			// ws_settings_.on_control_payload = &XHttpParser::on_control_payload;
			// ws_settings_.on_control_end = &XHttpParser::on_control_end;
			websocket_parser_settings_init(&ws_settings_);
			ws_settings_.on_frame_header = &XHttpParser::on_frame_header;
			ws_settings_.on_frame_body = &XHttpParser::on_frame_body;
			ws_settings_.on_frame_end = &XHttpParser::on_frame_end;
			websocket_parser_init(&ws_parser_);
			// Attention! Sets your <data> after websocket_parser_init
			ws_parser_.data = this;
#endif
		}
		~XHttpParser()
		{
		}

#ifdef USE_WEBSOCKET
		//升级websocket
		std::string BuildUpgradeBuf(const char* host, const char* path = "/")
		{
			//Connection: Upgrade：表示要升级协议
			//Upgrade: websocket：表示要升级到 websocket 协议。
			//Sec-WebSocket-Version: 13：表示 websocket 的版本。如果服务端不支持该版本，需要返回一个Sec-WebSocket-Version包含服务端支持的版本号。
			//Sec-WebSocket-Key：与后面服务端响应首部的Sec-WebSocket-Accept是配套的，提供基本的防护，比如恶意的连接，或者无意的连接。
			std::stringstream ss;
			ss << "XSocket: " << rand();
			std::string key = ss.str();
			int base64_len = Base64EncodeGetRequiredLength(key.size(), BASE64_FLAG_NOCRLF);
			std::string base64_key;
			base64_key.resize(base64_len);
			Base64Encode((const byte*)key.data(), key.size(), (char*)base64_key.data(), &base64_len, BASE64_FLAG_NOCRLF);
			base64_key.resize(base64_len);
			ss.clear();ss.str("");
			ss << "GET " << path << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
			<< "Origin: http://" << host << "\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Version: 13\r\n"
			<< "Sec-WebSocket-Key: " << base64_key << "\r\n"
			<< "\r\n";
			std::string str = ss.str();
			int len = str.size();
			//ParseBuf(str.c_str(), len);
			return str;
		}

		//接受升级websocket
		std::string BuildAcceptUpgradeBuf(const char* key, size_t key_len)
		{
			//Sec-WebSocket-Accept根据客户端请求首部的Sec-WebSocket-Key计算出来。
			//计算公式为：
			//将Sec-WebSocket-Key跟258EAFA5-E914-47DA-95CA-C5AB0DC85B11拼接。
			//通过 SHA1 计算出摘要，并转成 base64 字符串。
			std::string ws_key = std::string(key,key_len) + WEBSOCKET_UUID;
			SHA1_HASH hash_key = {0};
			SHA1(ws_key.data(), ws_key.size(), &hash_key);
			int base64_len = Base64EncodeGetRequiredLength(SHA1_HASH_SIZE, BASE64_FLAG_NOCRLF);
			std::string accept_key;
			accept_key.resize(base64_len);
			Base64Encode((const byte*)hash_key.bytes, SHA1_HASH_SIZE, (char*)accept_key.data(), &base64_len, BASE64_FLAG_NOCRLF);
			accept_key.resize(base64_len);
			std::stringstream ss;
			ss << "HTTP/1.1 101 Switching Protocols\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Sec-WebSocket-Accept: " << accept_key << "\r\n"
			<< "\r\n";
			std::string str = ss.str();
			int len = str.size();
			//ParseBuf(str.c_str(), len);
			return str;
		}

		static std::string BuildWebSocketBuf(const char* body, int body_len, int flags = WS_OP_TEXT|WS_FINAL_FRAME, uint32_t mask = 0)
		{
			std::string frame;
			if(mask) {
				mask = htonl(mask);
				flags |= WS_HAS_MASK;
			}
			size_t frame_len = websocket_calc_frame_size(flags, body_len);
			frame.resize(frame_len);
			websocket_build_frame((char*)frame.c_str(), flags, (char*)&mask, body, body_len);
			return frame;
		}

		// static std::string BuildWSPingBuf(const char* body, int body_len, int flags = WS_OP_TEXT|WS_FINAL_FRAME, uint32_t mask = 0)
		// {
		// 	return BuildWebSocketBuf();
		// }
#endif//
		
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

	protected:
		//
		static int on_message_begin (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_message_begin();
			}
			return 0;
		}
		static int on_url(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_url(at,length);
			}
			return 0;
		}
		static int on_status(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_status(at,length);
			}
			return 0;
		}
		static int on_header_field(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_header_field(at,length);
			}
			return 0;
		}
		static int on_header_value(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_header_value(at,length);
			}
			return 0;
		}
		static int on_headers_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_headers_complete();
			}
			return 0;
		}
		static int on_body(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_body(at,length);
			}
			return 0;
		}
		static int on_message_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_message_complete();
			}
			return 0;
		}
		static int on_chunk_header (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				return pThis->on_chunk_header();
			}
			return 0;
		}
		static int on_chunk_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
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
			url_ = strref(at,length);
			return 0;
		}
		inline int on_status(const char *at, size_t length)
		{
			status_ = strref(at,length);
			return 0;
		}
		inline int on_header_field(const char *at, size_t length)
		{
			fields_.resize(fields_.size()+1);
			fields_.back().name = strref(at,length);
			return 0;
		}
		inline int on_header_value(const char *at, size_t length)
		{
			fields_.back().value = strref(at,length);
			return 0;
		}
		inline int on_headers_complete ()
		{
			return 0;
		}
		inline int on_body(const char *at, size_t length)
		{
			body_ = strref(at,length);
			return 0;
		}
		inline int on_message_complete ()
		{
			done_ = true;
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
		// 	XHttpParser* pThis = (XHttpParser*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_begin(type);
		// 	}
		// 	return 0;
		// }
		
		// static int on_data_payload(void* data, const char* at, size_t length)
		// {
		// 	XHttpParser* pThis = (XHttpParser*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_payload(at, length);
		// 	}
		// 	return 0;
		// }
		
		// static int on_data_end(void* data)
		// {
		// 	XHttpParser* pThis = (XHttpParser*)data;
		// 	if(pThis) {
		// 		return pThis->on_data_end();
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_begin(void* data, ws_frame_type_t type)
		// {
		// 	XHttpParser* pThis = (XHttpParser*)data;
		// 	if(pThis) {
		// 		return pThis->on_control_begin(type);
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_payload(void* data, const char* at, size_t length)
		// {
		// 	XHttpParser* pThis = (XHttpParser*)data;
		// 	if(pThis) {
		// 		return pThis->on_control_payload(at, length);
		// 	}
		// 	return 0;
		// }
		
		// static int on_control_end(void* data)
		// {
		// 	XHttpParser* pThis = (XHttpParser*)data;
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
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_frame_header();
			}
			return 0;
		}

		static int on_frame_body(websocket_parser *parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_frame_body(at,length);
			}
			return 0;
		}

		static int on_frame_end(websocket_parser *parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
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
			body_ = strref(at,length);
			return 0;
		}

		inline int on_frame_end()
		{
			ws_done_ = true;
			return 0;
		}
#endif
	};
}

#endif//_H_XHTTP_PARSER_H_
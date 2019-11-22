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
#include <http_parser.h>
#ifdef USE_WEBSOCKET
//#include <ws_parser.h> //这个不能构建ws数据包
#include <websocket_parser.h> //这个可以解析和构建ws数据包
#endif//
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
		bool done_ = false;

		inline bool IsUpgrade() { return parser_.upgrade; }
		inline bool IsMessageDone() { return done_; }

#ifdef USE_WEBSOCKET
		websocket_parser_settings ws_settings_;
		websocket_parser ws_parser_;
		std::string ws_body_;
		inline bool GetOPCode() { return ws_parser_.flags & WS_OP_MASK; }
		inline bool	IsFinal() { return ws_parser_.flags & WS_FIN; }
#endif

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
			std::stringstream ss;
			ss << "GET " << path << " HTTP/1.1\r\n"
			<< "Upgrade: WebSocket\r\n"
			<< "Connection: Upgrade\r\n"
			<< "Host: " << host << "\r\n"
			<< "Origin: http://" << host << "\r\n"
			<< "WebSocket-Protocol: sample\r\n\r\n";
			std::string str = ss.str();
			int len = str.size();
			ParseBuf(str.c_str(), len);
			return str;
		}

		static std::string BuildWebSocketBuf(char* body, int body_len, int flags, const char* mask = nullptr, int mask_len = 0)
		{
			std::string frame;
			flags |= WS_FINAL_FRAME;
			char cmask[4] = {0};
			if(mask) {
				flags |= WS_HAS_MASK;
				if(mask_len < 4) {
					memcpy(cmask, mask, mask_len);
				} else {
					memcpy(cmask, mask, 4);
				}
			}
			size_t frame_len = websocket_calc_frame_size(flags, body_len);
			frame.resize(frame_len);
			websocket_build_frame((char*)frame.c_str(), flags, cmask, body, body_len);
			return frame;
		}
#endif//
		
		//解析数据包
		virtual int ParseBuf(const char* lpBuf, int & nBufLen) {
			int nParsed = 0;
			done_ = false;
			if(!IsUpgrade()) {
				nParsed = http_parser_execute(&parser_, &settings_, lpBuf, nBufLen);
				// if (IsUpgrade()) {
				// 	// 如果解析到websocket请求
				// } 
			} else {
#ifdef USE_WEBSOCKET
				nParsed = websocket_parser_execute(&ws_parser_, &ws_settings_, lpBuf, nBufLen);
#endif
			}
			nBufLen = nParsed;
			if(!done_) {
				return SOCKET_PACKET_FLAG_PENDING;
			}
			return SOCKET_PACKET_FLAG_COMPLETE;
		}

	protected:
		//
		static int on_message_begin (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_message_begin();
			}
			return 0;
		}
		static int on_url(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_url(at,length);
			}
			return 0;
		}
		static int on_status(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_status(at,length);
			}
			return 0;
		}
		static int on_header_field(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_header_field(at,length);
			}
			return 0;
		}
		static int on_header_value(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_header_value(at,length);
			}
			return 0;
		}
		static int on_headers_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_headers_complete();
			}
			return 0;
		}
		static int on_body(http_parser* parser, const char *at, size_t length)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_body(at,length);
			}
			return 0;
		}
		static int on_message_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_message_complete();
			}
			return 0;
		}
		static int on_chunk_header (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_chunk_header();
			}
			return 0;
		}
		static int on_chunk_complete (http_parser* parser)
		{
			XHttpParser* pThis = (XHttpParser*)parser->data;
			if(pThis) {
				pThis->on_chunk_complete();
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
				ws_body_.resize(ws_parser_.length); // allocate memory for frame body, if body exists
			}
			return 0;
		}

		inline int on_frame_body(const char *at, size_t length)
		{
			if (ws_parser_.flags & WS_HAS_MASK) {
				// if frame has mask, we have to copy and decode data via websocket_parser_copy_masked function
				websocket_parser_decode(&ws_body_[ws_parser_.offset], at, length, &ws_parser_);
			} else {
				memcpy(&ws_body_[ws_parser_.offset], at, length);
			}
			return 0;
		}

		inline int on_frame_end()
		{
			done_ = true;
			return 0;
		}
#endif
	};
}

#endif//_H_XHTTP_PARSER_H_
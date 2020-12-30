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
#ifndef _H_XWEBSOCKET_IMPL_H_
#define _H_XWEBSOCKET_IMPL_H_

#include "XSocketImpl.h"
#include "XCodec.h"
#include <sstream>
#include <strstream>

namespace XSocket {

	static const char* const WEBSOCKET_UUID  = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	/*!
	 *	@brief WSBuffer 定义.
	 *
	 *	封装WSBuffer，实现Websocket数据解析缓存
	 */
	template<class THolder>
	class WSBufferT
	{
		typedef WSBufferT<THolder> This;
	protected:
		THolder* holder_;
		//   0                   1                   2                   3
		//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//  +-+-+-+-+-------+-+-------------+-------------------------------+
		//  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		//  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		//  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
		//  | |1|2|3|       |K|             |                               |
		//  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		//  |     Extended payload length continued, if payload len == 127  |
		//  + - - - - - - - - - - - - - - - +-------------------------------+
		//  |                               |Masking-key, if MASK set to 1  |
		//  +-------------------------------+-------------------------------+
		//  | Masking-key (continued)       |          Payload Data         |
		//  +-------------------------------- - - - - - - - - - - - - - - - +
		//  :                     Payload Data continued ...                :
		//  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		//  |                     Payload Data continued ...                |
		//  +---------------------------------------------------------------+
		enum {
			// opcodes
			WS_OP_CONTINUE 	= 0x0,
			WS_OP_TEXT     	= 0x1,
			WS_OP_BINARY   	= 0x2,
			WS_OP_CLOSE    	= 0x8,
			WS_OP_PING     	= 0x9,
			WS_OP_PONG     	= 0xA,
			//
			WS_OP_MASK 		= 0xF,
			WS_FINAL_FRAME 	= 0x10,
			WS_HAS_MASK 	= 0x20,
		};
		uint8_t flags_ = 0;
		inline int GetOPCode() { return flags_ & WS_OP_MASK; }
		inline bool	IsFinal() { return flags_ & WS_FINAL_FRAME; }
		char mask_[4] = {0};
		const char* data_ = nullptr;
		size_t datalen_ = 0;
				
		inline static void decode(char * dst, const char * src, uint64_t len, const char mask[4]) {
			uint8_t mask_offset = 0;
			for(uint64_t i = 0; i < len; i++) {
				dst[i] = src[i] ^ mask[(i + mask_offset) % 4];
			}
		}
		inline static void encode(char * dst, const char * src, uint64_t len, const char mask[4]) {
			uint8_t mask_offset = 0;
			for(uint64_t i = 0; i < len; i++) {
				dst[i] = src[i] ^ mask[(i + mask_offset) % 4];
			}
		}
		
		inline static uint64_t calc_size(int flags, uint64_t data_len) {
			uint64_t size = data_len + 2; // body + 2 bytes of head
			if(data_len >= 126) {
				if(data_len > 0xFFFF) {
					size += 8;
				} else {
					size += 2;
				}
			}
			if(flags & WS_HAS_MASK) {
				size += 4;
			}

			return size;
		}

		inline static uint64_t build_header(char * frame, int flags, const char mask[4], uint64_t data_len) {
			uint64_t body_offset = 0;
			frame[0] = 0;
			frame[1] = 0;
			if(flags & WS_FINAL_FRAME) {
				frame[0] = (char) (1 << 7);
			}
			frame[0] |= flags & WS_OP_MASK;
			if(flags & WS_HAS_MASK) {
				frame[1] = (char) (1 << 7);
			}
			if(data_len < 126) {
				frame[1] |= data_len;
				body_offset = 2;
			} else if(data_len <= 0xFFFF) {
				frame[1] |= 126;
				frame[2] = (char) (data_len >> 8);
				frame[3] = (char) (data_len & 0xFF);
				body_offset = 4;
			} else {
				frame[1] |= 127;
				frame[2] = (char) ((data_len >> 56) & 0xFF);
				frame[3] = (char) ((data_len >> 48) & 0xFF);
				frame[4] = (char) ((data_len >> 40) & 0xFF);
				frame[5] = (char) ((data_len >> 32) & 0xFF);
				frame[6] = (char) ((data_len >> 24) & 0xFF);
				frame[7] = (char) ((data_len >> 16) & 0xFF);
				frame[8] = (char) ((data_len >>  8) & 0xFF);
				frame[9] = (char) ((data_len)       & 0xFF);
				body_offset = 10;
			}
			if(flags & WS_HAS_MASK) {
				memcpy(&frame[body_offset], mask, 4);
				body_offset += 4;
			}

			return body_offset;
		}

		inline static uint64_t build(char * frame, int flags, const char mask[4], const char * data, uint64_t data_len) {
			uint64_t body_offset = build_header(frame, flags, mask, data_len);
			if(flags & WS_HAS_MASK) {
				encode(&frame[body_offset], data, data_len, &frame[body_offset-4]);
			} else {
				memcpy(&frame[body_offset], data, data_len);
			}
			return body_offset + data_len;
		}

		bool enable_cache_ = false;//启用分片Cache
		std::string cache_buffer_;//分片时Cache数据
		uint8_t cache_flags_ = 0; //分片时Cache标志
		inline void ClearCache() { 
			cache_flags_ = 0;
			cache_buffer_.clear();
		}
		inline void DoCache(bool first, bool last) { 
			if(first) {
				ClearCache();
				cache_flags_ = flags_;
			}
			cache_buffer_.append(data_,datalen_); 
			if(last) {
				cache_flags_ |= WS_FINAL_FRAME;
				flags_ |= cache_flags_;
				data_ = cache_buffer_.data();
				datalen_ = cache_buffer_.size();
			}
		}

	public:
		WSBufferT(THolder* holder):holder_(holder)
		{
			
		}

		inline void EnableCache(bool bCache) { enable_cache_ = bCache; }
		inline bool IsCacheEnable() { return enable_cache_; }

		//构建数据包
		template<typename TBuffer>
		static void BuildBuf(TBuffer& out, const char* lpBody, int nBodyLen, int nFlags, uint32_t mask = 0)
		{
			int flags = 0;
			if(nFlags == SOCKET_PACKET_OP_CONTINUE) {
				flags = WS_OP_CONTINUE;
			} else {
				int nOPCode = nFlags&SOCKET_PACKET_OP_MASK;
				switch (nOPCode)
				{
				case SOCKET_PACKET_OP_PING:
					flags = WS_OP_PING|WS_FINAL_FRAME;
					break;
				case SOCKET_PACKET_OP_PONG:
					flags = WS_OP_PONG|WS_FINAL_FRAME;
					break;
				case SOCKET_PACKET_OP_CLOSE:
					flags = WS_OP_CLOSE|WS_FINAL_FRAME;
					break;
				default:
					{
						switch (nOPCode)
						{
						case SOCKET_PACKET_OP_TEXT:
							flags = WS_OP_TEXT;
							break;
						case SOCKET_PACKET_OP_BINARY:
							flags = WS_OP_BINARY;
							break;
						}
						if(nFlags&SOCKET_PACKET_FLAG_FINAL) {
							flags |= WS_FINAL_FRAME;
						}
					}
					break;
				}
			}
			if(mask) {
				//mask = htonl(mask);
				flags |= WS_HAS_MASK;
			}
			size_t frame_len = calc_size(flags, nBodyLen);
			size_t out_len = out.size();out.resize(out_len+frame_len);
			char* frame_buf = (char*)&out[out_len];
			build(frame_buf, flags, (char*)&mask, lpBody, nBodyLen);
		}

		//解析数据包
		int ParseBuf(const char* lpBuf, int & nBufLen) { 
			if(nBufLen < 2) {
				return SOCKET_PACKET_FLAG_PENDING;
			}
			const char* pCur = lpBuf;
			const char* pEnd = lpBuf + nBufLen;
			//flags
			flags_ = *pCur & WS_OP_MASK;
			if(*pCur & (1<<7)) {
				flags_ |= WS_FINAL_FRAME;
			}
			pCur++;

			//length
			size_t require = 0;
            size_t length  = (size_t)*pCur & 0x7F;
            if(*pCur & 0x80) {
                flags_ |= WS_HAS_MASK;
            }
            if(length >= 126) {
                if(length == 127) {
                	require = 8;
            	} else {
                    require = 2;
                }
                length = 0;
				pCur++;
				if(pCur+require > pEnd) {
					return SOCKET_PACKET_FLAG_PENDING;
				}
				while(require) {
                    length <<= 8;
                    length |= (unsigned char)*pCur;
                    require--;
                    pCur++;
                }
				pCur--;
			}
			pCur++;
			//mask
			if (flags_ & WS_HAS_MASK) {
                require = 4;
				if(pCur+require > pEnd) {
					return SOCKET_PACKET_FLAG_PENDING;
				}
				while(require) {
                    mask_[4 - require--] = *pCur;
                    pCur++;
                }
            }

			//data
			if(length) {
                require = length;
                //NOTIFY_CB(frame_header);
				if(pCur+require > pEnd) {
					return SOCKET_PACKET_FLAG_PENDING;
				}
				if (flags_ & WS_HAS_MASK) {
					decode((char*)pCur, pCur, length, mask_);
				}
            }
			data_ = pCur;
			datalen_ = length;
			nBufLen = (pCur + length) - lpBuf;

			int nFlags = SOCKET_PACKET_FLAG_COMPLETE;
			if (!IsFinal()) {
				if(enable_cache_) {
					DoCache(GetOPCode() != WS_OP_CONTINUE, false);
					return nFlags;
				}
			} else {
				nFlags |= SOCKET_PACKET_FLAG_FINAL;
				if(enable_cache_) {
					if (GetOPCode() == WS_OP_CONTINUE) {
						DoCache(false, true);
					}
				}
			}
			switch (GetOPCode())
			{
			case WS_OP_CLOSE:
				nFlags |= SOCKET_PACKET_OP_CLOSE;
				break;
			case WS_OP_PING:
				nFlags |= SOCKET_PACKET_OP_PING;
				break;
			case WS_OP_PONG:
				nFlags |= SOCKET_PACKET_OP_PONG;
				break;
			case WS_OP_TEXT:
				nFlags |= SOCKET_PACKET_OP_TEXT;
				break;
			case WS_OP_BINARY:
				nFlags |= SOCKET_PACKET_OP_BINARY;
				break;
			default:
				break;
			}
			return nFlags;
		}

		inline void clear() {
			flags_ = 0;
			memset(mask_, 0, sizeof(mask_));
			data_ = nullptr;
			datalen_ = 0;
			ClearCache();
		}

		inline const char* data() const { return data_; }
		inline size_t size() const { return datalen_; }
	};

	/*!
	 *	@brief WebSocketT 定义.
	 *
	 *	封装WebSocketT，实现Websocket收发数据功能
	 */
	template<class TBase>
	class WebSocketT : public TBase
	{
		typedef WebSocketT<TBase> This;
		typedef TBase Base;
	public:
		typedef typename Base::RecvBuffer RecvBuffer;
		typedef typename Base::SendBuffer SendBuffer;
	protected:
		friend WSBufferT<This>;
		typedef WSBufferT<This> WSBuffer;
		WSBuffer ws_buffer_;
	public:
		WebSocketT():ws_buffer_(this)
		{
		}
		~WebSocketT()
		{

		}

		inline int Close()
		{
			int ret = Base::Close();
			ws_buffer_.clear();
			return ret;
		}

		inline void EnableWSCache(bool bCache) { ws_buffer_.EnableCache(bCache); }
		inline bool IsWSCacheEnable() { return ws_buffer_.IsCacheEnable(); }

		//构建数据包
		template<typename TBuffer>
		inline static void BuildWSBuf(TBuffer& out, const char* lpBody, int nBodyLen
		, int nFlags =  SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL, uint32_t mask = 0)
		{
			WSBuffer::BuildBuf(out, lpBody, nBodyLen, nFlags, mask);
		}

		void SendWSBuf(const char* lpBody, int nBodyLen
		, int nFlags = SOCKET_PACKET_OP_TEXT|SOCKET_PACKET_FLAG_FINAL, uint32_t mask = 0)
		{
			ws_buffer_.BuildBuf(Base::SendBuf(), lpBody, nBodyLen, nFlags, mask);
			Base::SendBufDirect();
		}

	protected:
		//
		//解析数据包
		virtual int ParseBuf(const char* lpBuf, int & nBufLen) { 
			int nFlags = ws_buffer_.ParseBuf(lpBuf, nBufLen);
			if (!(nFlags & SOCKET_PACKET_FLAG_COMPLETE)) {
				return nFlags;
			}
			if(ws_buffer_.IsCacheEnable()) {
				//Cache下，分片不调用OnWSMessage，分片接收结束时再调用OnWSMessage
				if(!(nFlags&SOCKET_PACKET_FLAG_FINAL)) {
					return nFlags;
				}
			}
			int nOPCode = nFlags&SOCKET_PACKET_OP_MASK;
			switch (nOPCode)
			{
			case SOCKET_PACKET_OP_PING:
				OnWSPing();
				break;
			case SOCKET_PACKET_OP_PONG:
				OnWSPong();
				break;
			case SOCKET_PACKET_OP_CLOSE:
				OnWSClose();
				break;
			default:
				OnWSMessage(ws_buffer_.data(), ws_buffer_.size(), nFlags);
				break;
			}
			return nFlags;
		}

		virtual void OnWSPing()
		{
			//Pong();
		}
		virtual void OnWSPong()
		{
			//
		}
		virtual void OnWSClose()
		{
			Base::Trigger(FD_CLOSE, 0);
		}
		virtual void OnWSMessage(const char* lpBuf, int nBufLen, int nFlags)
		{

		}
	};

}

#endif//_H_XWEBSOCKET_IMPL_H_
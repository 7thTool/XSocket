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
#ifndef _H_XSOCKET_CODEC_H_
#define _H_XSOCKET_CODEC_H_

#include "XSocketDef.h"
#include <limits.h>
#if USE_ZLIB
#include <zlib.h>
#endif
#if USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#include <string>

namespace XSocket {

	int dehexlen(int inlen);
	int dehex(const unsigned char *in, int inlen, unsigned char *out, int outlen);
	int enhexlen(int inlen);
	int enhex(const unsigned char *in, int inlen, unsigned char *out, int outlen);

	void tohex(unsigned char *in, unsigned char *out, int len);
	void fromhex(unsigned char *in, unsigned char *out, int len);

	std::string format_hex(const uint8_t *s, size_t len);
	inline std::string format_hex(uint8_t c) { return format_hex(&c, 1); }
	inline std::string format_hex(const std::string &s) { return format_hex(reinterpret_cast<const uint8_t *>(s.data()), s.size()); }

	#define BASE64_FLAG_NONE	0
	#define BASE64_FLAG_NOPAD	1
	#define BASE64_FLAG_NOCRLF  2

	int en64len(int inlen, size_t dwFlags = BASE64_FLAG_NONE);
    int Base64Encode(
        const byte *pbSrcData,
        int nSrcLen,
        char* szDest,
        int nDestLen,
        size_t dwFlags = BASE64_FLAG_NONE);
	unsigned char* en64(const unsigned char *in, unsigned char *out, int inlen);
	int de64len(int inlen);
	inline int Base64Decode(
        const char* szSrc,
        int nSrcLen,
        byte *pbDest,
        int nDestLen);
	int de64(const char *in, unsigned char *out, int maxlen);

	// SHA1_CTX - This must be initialised using SHA1Initd. Do not modify the contents of this structure directly.
	typedef struct
	{
		uint32_t        State[5];
		uint32_t        Count[2];
		uint8_t         Buffer[64];
	} SHA1_CTX;

	#define SHA1_HASH_SIZE           ( 160 / 8 )

	void SHA1Init( SHA1_CTX* Context);
	void SHA1Update(SHA1_CTX* Context, void const* Buffer, uint32_t BufferSize);
	void SHA1Final(SHA1_CTX* Context, uint8_t* Digest);
	//  Combines SHA1Init, SHA1Update, and SHA1Final into one function. Calculates the SHA1 hash of the buffer.
	void SHA1(void  const* Buffer, uint32_t BufferSize, uint8_t* Digest);

#if USE_ZLIB
	/* Compress gzip data */
	/* data 原数据 ndata 原数据长度 zdata 压缩后数据 nzdata 压缩后长度 */
	int gzcompress(Bytef *data, uLong ndata,
				Bytef *zdata, uLong *nzdata);
	/* Uncompress gzip data */
	/* zdata 数据 nzdata 原数据长度 data 解压后数据 ndata 解压后长度 */
	int gzdecompress(Byte *zdata, uLong nzdata,
					Byte *data, uLong *ndata);
#endif

#if USE_OPENSSL

	int base64_encode(char *str, int str_len, char *encode, int encode_len);
	int base64_decode(char *str, int str_len, char *decode, int decode_len);

#endif

}

#endif//_H_XSOCKET_CODEC_H_

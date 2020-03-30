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
#ifndef _H_XCODEC_H_
#define _H_XCODEC_H_

#include "XSocketDef.h"
#include <limits.h>
#ifdef USE_ZLIB
#include <zlib.h>
#endif
#ifdef USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

namespace XSocket {

//=======================================================================
// HexEncode, HexDecode
//
// Support for encoding/decoding binary with hex encoding
//=======================================================================
//

inline int HexEncodeGetRequiredLength(int nSrcLen)
{
	int64_t nRet64=2*static_cast<int64_t>(nSrcLen)+1;
	ENSURE(nRet64 <= INT_MAX && nRet64 >= INT_MIN);
	int nRet = static_cast<int>(nRet64);
	return nRet;
}

inline int HexDecodeGetRequiredLength(int nSrcLen)
{
	return nSrcLen/2;
}

inline bool HexEncode(
	const byte *pbSrcData,
	int nSrcLen,
	char* szDest,
	int *pnDestLen)
{
	static const char s_chHexChars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
										  'A', 'B', 'C', 'D', 'E', 'F'};

	if (!pbSrcData || !szDest || !pnDestLen)
	{
		return false;
	}

	if(*pnDestLen < HexEncodeGetRequiredLength(nSrcLen))
	{
		ASSERT(false);
		return false;
	}

	int nRead = 0;
	int nWritten = 0;
	byte ch;
	while (nRead < nSrcLen)
	{
		ch = *pbSrcData++;
		nRead++;
		*szDest++ = s_chHexChars[(ch >> 4) & 0x0F];
		*szDest++ = s_chHexChars[ch & 0x0F];
		nWritten += 2;
	}

	*pnDestLen = nWritten;

	return true;
}

const char HEX_INVALID_CHAR = ((char)(-1));

//Get the decimal value of a hexadecimal character
inline char GetHexValue(char ch)
{
	if (ch >= '0' && ch <= '9')
		return (ch - '0');
	if (ch >= 'A' && ch <= 'F')
		return (ch - 'A' + 10);
	if (ch >= 'a' && ch <= 'f')
		return (ch - 'a' + 10);
	return HEX_INVALID_CHAR;
}

inline bool HexDecode(
	const char* pSrcData,
	int nSrcLen,
	byte* pbDest,
	int* pnDestLen)
{
	if (!pSrcData || !pbDest || !pnDestLen)
	{
		return false;
	}

	if(*pnDestLen < HexDecodeGetRequiredLength(nSrcLen))
	{
		ASSERT(false);
		return false;
	}

	int nRead = 0;
	int nWritten = 0;
	while (nRead < nSrcLen)
	{
		char ch1 = GetHexValue((char)*pSrcData++);
		char ch2 = GetHexValue((char)*pSrcData++);
		if ((ch1==HEX_INVALID_CHAR) || (ch2==HEX_INVALID_CHAR))
		{
			return false;
		}
		*pbDest++ = (byte)(16*ch1+ch2);
		nWritten++;
		nRead += 2;
	}

	*pnDestLen = nWritten;
	return true;
}

inline std::string format_hex(const uint8_t *s, size_t len) {
  const char LOWER_XDIGITS[] = "0123456789abcdef";
  std::string res;
  res.resize(len * 2);

  for (size_t i = 0; i < len; ++i) {
    auto c = s[i];

    res[i * 2] = LOWER_XDIGITS[c >> 4];
    res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

inline std::string format_hex(uint8_t c) {
  return format_hex(&c, 1);
}

inline std::string format_hex(const std::string &s) {
  return format_hex(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

//=======================================================================
// Base64Encode/Base64Decode
// compliant with RFC 2045
//=======================================================================
//
#define BASE64_FLAG_NONE	0
#define BASE64_FLAG_NOPAD	1
#define BASE64_FLAG_NOCRLF  2

inline int Base64EncodeGetRequiredLength(
	int nSrcLen,
	size_t dwFlags = BASE64_FLAG_NONE)
{
	int64_t nSrcLen4=static_cast<int64_t>(nSrcLen)*4;
	ENSURE(nSrcLen4 <= INT_MAX);

	int nRet = static_cast<int>(nSrcLen4/3);

	if ((dwFlags & BASE64_FLAG_NOPAD) == 0)
		nRet += nSrcLen % 3;

	int nCRLFs = nRet / 76 + 1;
	int nOnLastLine = nRet % 76;

	if (nOnLastLine)
	{
		if (nOnLastLine % 4)
			nRet += 4-(nOnLastLine % 4);
	}

	nCRLFs *= 2;

	if ((dwFlags & BASE64_FLAG_NOCRLF) == 0)
		nRet += nCRLFs;

	return nRet;
}

inline int Base64DecodeGetRequiredLength(int nSrcLen)
{
	return nSrcLen;
}

inline bool Base64Encode(
	const byte *pbSrcData,
	int nSrcLen,
	char* szDest,
	int *pnDestLen,
	size_t dwFlags = BASE64_FLAG_NONE)
{
	static const char s_chBase64EncodingTable[64] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',	'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
		'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

	if (!pbSrcData || !szDest || !pnDestLen)
	{
		return false;
	}

	if(*pnDestLen < Base64EncodeGetRequiredLength(nSrcLen, dwFlags))
	{
		ASSERT(false);
		return false;
	}

	int nWritten( 0 );
	int nLen1( (nSrcLen/3)*4 );
	int nLen2( nLen1/76 );
	int nLen3( 19 );

	for (int i=0; i<=nLen2; i++)
	{
		if (i==nLen2)
			nLen3 = (nLen1%76)/4;

		for (int j=0; j<nLen3; j++)
		{
			size_t dwCurr(0);
			for (int n=0; n<3; n++)
			{
				dwCurr |= *pbSrcData++;
				dwCurr <<= 8;
			}
			for (int k=0; k<4; k++)
			{
				byte b = (byte)(dwCurr>>26);
				*szDest++ = s_chBase64EncodingTable[b];
				dwCurr <<= 6;
			}
		}
		nWritten+= nLen3*4;

		if ((dwFlags & BASE64_FLAG_NOCRLF)==0)
		{
			*szDest++ = '\r';
			*szDest++ = '\n';
			nWritten+= 2;
		}
	}

	if (nWritten && (dwFlags & BASE64_FLAG_NOCRLF)==0)
	{
		szDest-= 2;
		nWritten -= 2;
	}

	nLen2 = (nSrcLen%3) ? (nSrcLen%3 + 1) : 0;
	if (nLen2)
	{
		size_t dwCurr(0);
		for (int n=0; n<3; n++)
		{
			if (n<(nSrcLen%3))
				dwCurr |= *pbSrcData++;
			dwCurr <<= 8;
		}
		for (int k=0; k<nLen2; k++)
		{
			byte b = (byte)(dwCurr>>26);
			*szDest++ = s_chBase64EncodingTable[b];
			dwCurr <<= 6;
		}
		nWritten+= nLen2;
		if ((dwFlags & BASE64_FLAG_NOPAD)==0)
		{
			nLen3 = nLen2 ? 4-nLen2 : 0;
			for (int j=0; j<nLen3; j++)
			{
				*szDest++ = '=';
			}
			nWritten+= nLen3;
		}
	}

	*pnDestLen = nWritten;
	return true;
}

inline int DecodeBase64Char(unsigned int ch)
{
	// returns -1 if the character is invalid
	// or should be skipped
	// otherwise, returns the 6-bit code for the character
	// from the encoding table
	if (ch >= 'A' && ch <= 'Z')
		return ch - 'A' + 0;	// 0 range starts at 'A'
	if (ch >= 'a' && ch <= 'z')
		return ch - 'a' + 26;	// 26 range starts at 'a'
	if (ch >= '0' && ch <= '9')
		return ch - '0' + 52;	// 52 range starts at '0'
	if (ch == '+')
		return 62;
	if (ch == '/')
		return 63;
	return -1;
}

inline bool Base64Decode(
	const char* szSrc,
	int nSrcLen,
	byte *pbDest,
	int *pnDestLen)
{
	// walk the source buffer
	// each four character sequence is converted to 3 bytes
	// CRLFs and =, and any characters not in the encoding table
	// are skiped

	if (szSrc == NULL || pnDestLen == NULL)
	{
		ASSERT(false);
		return false;
	}

	const char* szSrcEnd = szSrc + nSrcLen;
	int nWritten = 0;

	bool bOverflow = (pbDest == NULL) ? true : false;

	while (szSrc < szSrcEnd &&(*szSrc) != 0)
	{
		size_t dwCurr = 0;
		int i;
		int nBits = 0;
		for (i=0; i<4; i++)
		{
			if (szSrc >= szSrcEnd)
				break;
			int nCh = DecodeBase64Char(*szSrc);
			szSrc++;
			if (nCh == -1)
			{
				// skip this char
				i--;
				continue;
			}
			dwCurr <<= 6;
			dwCurr |= nCh;
			nBits += 6;
		}

		if(!bOverflow && nWritten + (nBits/8) > (*pnDestLen))
			bOverflow = true;

		// dwCurr has the 3 bytes to write to the output buffer
		// left to right
		dwCurr <<= 24-nBits;
		for (i=0; i<nBits/8; i++)
		{
			if(!bOverflow)
			{
				*pbDest = (byte) ((dwCurr & 0x00ff0000) >> 16);
				pbDest++;
			}
			dwCurr <<= 8;
			nWritten++;
		}

	}

	*pnDestLen = nWritten;

	if(bOverflow)
	{
		if(pbDest != NULL)
		{
			ASSERT(false);
		}

		return false;
	}

	return true;
}


//=======================================================================
// SHA1
// 
//=======================================================================
//
// SHA1_CTX - This must be initialised using SHA1Initd. Do not modify the contents of this structure directly.
typedef struct
{
    uint32_t        State[5];
    uint32_t        Count[2];
    uint8_t         Buffer[64];
} SHA1_CTX;

#define SHA1_HASH_SIZE           ( 160 / 8 )

typedef struct
{
    uint8_t      bytes [SHA1_HASH_SIZE];
} SHA1_HASH;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  SHA1Init
//
//  Initialises an SHA1 Context. Use this to initialise/reset a context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    SHA1Init
    (
        SHA1_CTX*        Context         // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  SHA1Update
//
//  Adds data to the SHA1 context. This will process the data and update the internal state of the context. Keep on
//  calling this function until all the data has been added. Then call SHA1Final to calculate the hash.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    SHA1Update
    (
        SHA1_CTX*        Context,        // [in out]
        void const*         Buffer,         // [in]
        uint32_t            BufferSize      // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  SHA1Final
//
//  Performs the final calculation of the hash and returns the digest (20 byte buffer containing 160bit hash). After
//  calling this, SHA1Initd must be used to reuse the context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    SHA1Final
    (
        SHA1_CTX*        Context,        // [in out]
        SHA1_HASH*          Digest          // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha1Calculate
//
//  Combines SHA1Init, SHA1Update, and SHA1Final into one function. Calculates the SHA1 hash of the buffer.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    SHA1
    (
        void  const*        Buffer,         // [in]
        uint32_t            BufferSize,     // [in]
        SHA1_HASH*          Digest          // [in]
    );


#ifdef USE_ZLIB
/* Compress gzip data */
/* data 原数据 ndata 原数据长度 zdata 压缩后数据 nzdata 压缩后长度 */
int gzcompress(Bytef *data, uLong ndata,
               Bytef *zdata, uLong *nzdata);
/* Uncompress gzip data */
/* zdata 数据 nzdata 原数据长度 data 解压后数据 ndata 解压后长度 */
int gzdecompress(Byte *zdata, uLong nzdata,
                 Byte *data, uLong *ndata);
#endif

}

#endif//_H_XCODEC_H_

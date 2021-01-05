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
#include "XCodec.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Decide whether to use the Little-Endian shortcut. If the shortcut is not used then the code will work correctly
// on either big or little endian, however if we do know it is a little endian architecture we can speed it up a bit.
// Note, there are TWO places where USE_LITTLE_ENDIAN_SHORTCUT is used. They MUST be paired together.
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
    // gcc defines __BYTE_ORDER__ so if it says its little endian we can use that.
    #define USE_LITTLE_ENDIAN_SHORTCUT
#elif defined( _WIN32 )
    // Windows is always little endian so we can use that.
    #define USE_LITTLE_ENDIAN_SHORTCUT
#endif

namespace XSocket {

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

    inline int dehexlen(int nSrcLen)
    {
        return nSrcLen/2;
    }

    inline int dehex(
        const unsigned char* pSrcData,
        int nSrcLen,
        unsigned char* pbDest,
        int nDestLen)
    {
        if (!pSrcData || !pbDest || !nDestLen)
        {
            return -1;
        }

        if(nDestLen < dehexlen(nSrcLen))
        {
            ASSERT(0);
            return -1;
        }

        int nRead = 0;
        int nWritten = 0;
        while (nRead < nSrcLen)
        {
            char ch1 = GetHexValue((char)*pSrcData++);
            char ch2 = GetHexValue((char)*pSrcData++);
            if ((ch1==HEX_INVALID_CHAR) || (ch2==HEX_INVALID_CHAR))
            {
                return -1;
            }
            *pbDest++ = (unsigned char)(16*ch1+ch2);
            nWritten++;
            nRead += 2;
        }

        return nWritten;
    }

    inline int enhexlen(int nSrcLen)
    {
        return nSrcLen * 2;
    }

    inline int enhex(
        const unsigned char *pbSrcData,
        int nSrcLen,
        unsigned char* szDest,
        int nDestLen)
    {
        static const char s_chHexChars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                                            'A', 'B', 'C', 'D', 'E', 'F'};

        if (!pbSrcData || !szDest || !nDestLen)
        {
            return -1;
        }

        if(nDestLen < enhexlen(nSrcLen))
        {
            ASSERT(0);
            return -1;
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

        return nWritten;
    }

	unsigned char hex[] = "0123456789ABCDEF";

	void tohex(unsigned char *in, unsigned char *out, int len) {
		int i;

		for (i = 0; i<len; i++) {
			out[(i << 1)] = hex[(in[i] >> 4)];
			out[(i << 1) + 1] = hex[(in[i] & 0x0F)];
		}
		out[(i << 1)] = 0;
	}

	void fromhex(unsigned char *in, unsigned char *out, int len) {
		char *c1, *c2;
		for (; len > 0; len--) {
			c1 = strchr((char *)hex, *in++);
			c2 = strchr((char *)hex, *in++);
			if (c1 && c2) {
				*out++ = ((unsigned char)((unsigned char *)c1 - hex) << 4) + (unsigned char)((unsigned char *)c2 - hex);
			}
		}
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

	static const unsigned char base64digits[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD 255
	static const unsigned char base64val[] = {
		BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
		BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
		BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
		52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
		BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
		15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
		BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
		41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
	};
#define DECODE64(c)  ((c > 32 && c<127)? base64val[(int)c] : BAD)

    inline int en64len(
        int nSrcLen,
        size_t dwFlags)
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

    inline int Base64Encode(
        const byte *pbSrcData,
        int nSrcLen,
        char* szDest,
        int nDestLen,
        size_t dwFlags)
    {
        static const char s_chBase64EncodingTable[64] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',	'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
            'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

        if (!pbSrcData || !szDest || !nDestLen)
        {
            return -1;
        }

        if(nDestLen < en64len(nSrcLen, dwFlags))
        {
            ASSERT(0);
            return -1;
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

        return nWritten;
    }

	unsigned char* en64(const unsigned char *in, unsigned char *out, int inlen)
	{
		for (; inlen > 0; inlen -= 3, in += 3)
		{

			*out++ = base64digits[in[0] >> 2];
			*out++ = base64digits[((in[0] & 3) << 4) | ((inlen > 1) ? (in[1] >> 4) : 0)];
			*out++ = (inlen > 1) ? base64digits[((in[1] << 2) & 0x3c) | ((inlen > 2) ? (in[2] >> 6) : 0)] : '=';
			*out++ = (inlen > 2) ? base64digits[in[2] & 0x3f] : '=';
		}
		*out = '\0';
		return out;
	}

    inline int de64len(int nSrcLen)
    {
        return nSrcLen;
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

    inline int Base64Decode(
        const char* szSrc,
        int nSrcLen,
        byte *pbDest,
        int nDestLen)
    {
        // walk the source buffer
        // each four character sequence is converted to 3 bytes
        // CRLFs and =, and any characters not in the encoding table
        // are skiped

        if (szSrc == NULL || nDestLen == NULL)
        {
            ASSERT(0);
            return -1;
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

            if(!bOverflow && nWritten + (nBits/8) > (nDestLen))
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

        if(bOverflow)
        {
            if(pbDest != NULL)
            {
                ASSERT(0);
            }
            
            return -1;
        }

        return nWritten;
    }

	int de64(const char *in, unsigned char *out, int maxlen)
	{
		int len = 0;
		register unsigned char digit1, digit2, digit3, digit4;

		if (in[0] == '+' && in[1] == ' ')
			in += 2;
		if (*in == '\r')
			return(0);

		do {
			digit1 = in[0];
			if (DECODE64(digit1) == BAD)
				return(-1);
			digit2 = in[1];
			if (DECODE64(digit2) == BAD)
				return(-1);
			digit3 = in[2];
			if (digit3 != '=' && DECODE64(digit3) == BAD)
				return(-1);
			digit4 = in[3];
			if (digit4 != '=' && DECODE64(digit4) == BAD)
				return(-1);
			in += 4;
			*out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
			++len;
			if (digit3 != '=')
			{
				*out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
				++len;
				if (digit4 != '=')
				{
					*out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
					++len;
				}
			}
		} while
			(*in && *in != '\r' && digit4 != '=' && (maxlen -= 4) >= 4);

		return (len);
	}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //  TYPES
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    typedef union
    {
        uint8_t     c [64];
        uint32_t    l [16];
    } CHAR64LONG16;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //  INTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Endian neutral macro for loading 32 bit value from 4 byte array (in big endian form).
    #define LOAD32H(x, y)                           \
        { x = ((uint32_t)((y)[0] & 255)<<24) |     \
            ((uint32_t)((y)[1] & 255)<<16) |     \
            ((uint32_t)((y)[2] & 255)<<8)  |     \
            ((uint32_t)((y)[3] & 255)); }

    #define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

    // blk0() and blk() perform the initial expand.
    #ifdef USE_LITTLE_ENDIAN_SHORTCUT
        #define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) | (rol(block->l[i],8)&0x00FF00FF))
    #else
        #define blk0(i) block->l[i]
    #endif

    #define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15] ^ block->l[(i+8)&15] ^ block->l[(i+2)&15] ^ block->l[i&15],1))

    // (R0+R1), R2, R3, R4 are the different operations used in SHA1
    #define R0(v,w,x,y,z,i)  z += ((w&(x^y))^y)     + blk0(i)+ 0x5A827999 + rol(v,5); w=rol(w,30);
    #define R1(v,w,x,y,z,i)  z += ((w&(x^y))^y)     + blk(i) + 0x5A827999 + rol(v,5); w=rol(w,30);
    #define R2(v,w,x,y,z,i)  z += (w^x^y)           + blk(i) + 0x6ED9EBA1 + rol(v,5); w=rol(w,30);
    #define R3(v,w,x,y,z,i)  z += (((w|x)&y)|(w&x)) + blk(i) + 0x8F1BBCDC + rol(v,5); w=rol(w,30);
    #define R4(v,w,x,y,z,i)  z += (w^x^y)           + blk(i) + 0xCA62C1D6 + rol(v,5); w=rol(w,30);

    // Loads the 128 bits from ByteArray into WordArray, treating ByteArray as big endian data
    #ifdef USE_LITTLE_ENDIAN_SHORTCUT
        #define Load128BitsAsWords( WordArray, ByteArray )  \
            memcpy( WordArray, ByteArray, 64 )
    #else
        #define Load128BitsAsWords( WordArray, ByteArray )      \
        {                                                       \
            uint32_t i;                                         \
            for( i=0; i<16; i++ )                               \
            {                                                   \
                LOAD32H( (WordArray)[i], (ByteArray)+(i*4) );   \
            }                                                   \
        }
    #endif

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //  TransformFunction
    //
    //  Hash a single 512-bit block. This is the core of the algorithm
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    static
    void
        TransformFunction
        (
            uint32_t            state[5],
            uint8_t const       buffer[64]
        )
    {
        uint32_t            a;
        uint32_t            b;
        uint32_t            c;
        uint32_t            d;
        uint32_t            e;
        uint8_t             workspace[64];
        CHAR64LONG16*       block = (CHAR64LONG16*) workspace;

        Load128BitsAsWords( block->l, buffer );

        // Copy context->state[] to working vars
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];

        // 4 rounds of 20 operations each. Loop unrolled.
        R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
        R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
        R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
        R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
        R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
        R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
        R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
        R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
        R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
        R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
        R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
        R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
        R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
        R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
        R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
        R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
        R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
        R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
        R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
        R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

        // Add the working vars back into context.state[]
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

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
        )
    {
        // SHA1 initialisation constants
        Context->State[0] = 0x67452301;
        Context->State[1] = 0xEFCDAB89;
        Context->State[2] = 0x98BADCFE;
        Context->State[3] = 0x10325476;
        Context->State[4] = 0xC3D2E1F0;
        Context->Count[0] = 0;
        Context->Count[1] = 0;
    }

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
            void  const*        Buffer,         // [in]
            uint32_t            BufferSize      // [in]
        )
    {
        uint32_t    i;
        uint32_t    j;

        j = (Context->Count[0] >> 3) & 63;
        if( (Context->Count[0] += BufferSize << 3) < (BufferSize << 3) )
        {
            Context->Count[1]++;
        }

        Context->Count[1] += (BufferSize >> 29);
        if( (j + BufferSize) > 63 )
        {
            i = 64 - j;
            memcpy( &Context->Buffer[j], Buffer, i );
            TransformFunction(Context->State, Context->Buffer);
            for( ; i + 63 < BufferSize; i += 64 )
            {
                TransformFunction(Context->State, (uint8_t*)Buffer + i);
            }
            j = 0;
        }
        else
        {
            i = 0;
        }

        memcpy( &Context->Buffer[j], &((uint8_t*)Buffer)[i], BufferSize - i );
    }

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
            uint8_t*          Digest          // [in]
        )
    {
        uint32_t    i;
        uint8_t     finalcount[8];

        for( i=0; i<8; i++ )
        {
            finalcount[i] = (unsigned char)((Context->Count[(i >= 4 ? 0 : 1)]
            >> ((3-(i & 3)) * 8) ) & 255);  // Endian independent
        }
        SHA1Update( Context, (uint8_t*)"\x80", 1 );
        while( (Context->Count[0] & 504) != 448 )
        {
            SHA1Update( Context, (uint8_t*)"\0", 1 );
        }

        SHA1Update( Context, finalcount, 8 );  // Should cause a Sha1TransformFunction()
        for( i=0; i<SHA1_HASH_SIZE; i++ )
        {
            Digest[i] = (uint8_t)((Context->State[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
        }
    }

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
            uint8_t*          Digest          // [in]
        )
    {
        SHA1_CTX context;

        SHA1Init( &context );
        SHA1Update( &context, Buffer, BufferSize );
        SHA1Final( &context, Digest );
    }

#if USE_ZLIB
    /* Compress gzip data */
    /* data 原数据 ndata 原数据长度 zdata 压缩后数据 nzdata 压缩后长度 */
    int gzcompress(Bytef *data, uLong ndata,
                Bytef *zdata, uLong *nzdata)
    {
        z_stream c_stream;
        int err = 0;

        if (data && ndata > 0) {
            c_stream.zalloc = NULL;
            c_stream.zfree = NULL;
            c_stream.opaque = NULL;
            //只有设置为MAX_WBITS + 16才能在在压缩文本中带header和trailer
            if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                            MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
            c_stream.next_in = data;
            c_stream.avail_in = ndata;
            c_stream.next_out = zdata;
            c_stream.avail_out = *nzdata;
            while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) {
                if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
            }
            if (c_stream.avail_in != 0) return c_stream.avail_in;
            for (;;) {
                if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
                if (err != Z_OK) return -1;
            }
            if (deflateEnd(&c_stream) != Z_OK) return -1;
            *nzdata = c_stream.total_out;
            return 0;
        }
        return -1;
    }

    /* Uncompress gzip data */
    /* zdata 数据 nzdata 原数据长度 data 解压后数据 ndata 解压后长度 */
    int gzdecompress(Byte *zdata, uLong nzdata,
                    Byte *data, uLong *ndata)
    {
        int err = 0;
        z_stream d_stream = { 0 }; /* decompression stream */
        static char dummy_head[2] = {
            0x8 + 0x7 * 0x10,
            (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
        };
        d_stream.zalloc = NULL;
        d_stream.zfree = NULL;
        d_stream.opaque = NULL;
        d_stream.next_in = zdata;
        d_stream.avail_in = 0;
        d_stream.next_out = data;
        //只有设置为MAX_WBITS + 16才能在解压带header和trailer的文本
        if (inflateInit2(&d_stream, MAX_WBITS + 16) != Z_OK) return -1;
        //if(inflateInit2(&d_stream, 47) != Z_OK) return -1;
        while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
            d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
            if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
            if (err != Z_OK) {
                if (err == Z_DATA_ERROR) {
                    d_stream.next_in = (Bytef*)dummy_head;
                    d_stream.avail_in = sizeof(dummy_head);
                    if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) {
                        return -1;
                    }
                }
                else return -1;
            }
        }
        if (inflateEnd(&d_stream) != Z_OK) return -1;
        *ndata = d_stream.total_out;
        return 0;
    }
#endif

#if USE_OPENSSL

    int base64_encode(char *str, int str_len, char *encode, int encode_len) {
        int ret = -1;
        BIO *bmem, *b64;
        BUF_MEM *bptr;
        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, str, str_len);
        BIO_flush(b64);
        BIO_get_mem_ptr(b64, &bptr);
        if (bptr->length <= encode_len) {
            ret = bptr->length;
            memcpy(encode, bptr->data, bptr->length);
        }
        BIO_free_all(b64);
        return ret;
    }

    int base64_decode(char *str, int str_len, char *decode, int decode_len) {
        int ret = -1;
        BIO *b64, *bmem;
        BUF_MEM *bptr;
        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new_mem_buf(str, str_len);
        bmem = BIO_push(b64, bmem);
        BIO_get_mem_ptr(b64, &bptr);
        if (bptr->length <= decode_len) {
            ret = BIO_read(bmem, decode, decode_len);
        }
        BIO_free_all(b64);
        return ret;
    }

#endif

}

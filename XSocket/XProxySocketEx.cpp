#include "XProxySocketEx.h"

#ifdef WIN32
#include <atlenc.h>
#endif//

namespace XSocket {

#ifdef WIN32

int ProxyHelper::Base64Encode(const char *pbSrcData, int nSrcLen, LPSTR szDest,int nDestLen)
{
	if(ATL::Base64Encode((const byte*)pbSrcData,nSrcLen,szDest,&nDestLen,ATL_BASE64_FLAG_NOCRLF)) {
		return nDestLen;
	}
	return -1;
}

#else

namespace ATL {

//=======================================================================
// Base64Encode/Base64Decode
// compliant with RFC 2045
//=======================================================================
//
#define ATL_BASE64_FLAG_NONE	0
#define ATL_BASE64_FLAG_NOPAD	1
#define ATL_BASE64_FLAG_NOCRLF  2

inline int Base64EncodeGetRequiredLength(int nSrcLen, int nFlags=ATL_BASE64_FLAG_NONE)
{
	__int64 nSrcLen4=static_cast<__int64>(nSrcLen)*4;

	int nRet = static_cast<int>(nSrcLen4/3);

	if ((nFlags & ATL_BASE64_FLAG_NOPAD) == 0)
		nRet += nSrcLen % 3;

	int nCRLFs = nRet / 76 + 1;
	int nOnLastLine = nRet % 76;

	if (nOnLastLine)
	{
		if (nOnLastLine % 4)
			nRet += 4-(nOnLastLine % 4);
	}

	nCRLFs *= 2;

	if ((nFlags & ATL_BASE64_FLAG_NOCRLF) == 0)
		nRet += nCRLFs;

	return nRet;
}

inline int Base64Encode(
						const char *pbSrcData,
						int nSrcLen,
						char* szDest,
						int *pnDestLen,
						int nFlags = ATL_BASE64_FLAG_NONE) throw()
{
	static const char s_chBase64EncodingTable[64] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',	'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
		'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

		if (!pbSrcData)
		{
			return 0;
		}

		if (!szDest || !pnDestLen)
		{
			return Base64EncodeGetRequiredLength(nSrcLen, nFlags);
		}

		if(*pnDestLen < Base64EncodeGetRequiredLength(nSrcLen, nFlags))
		{
			return 0;
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
				int nCurr(0);
				for (int n=0; n<3; n++)
				{
					nCurr |= *pbSrcData++;
					nCurr <<= 8;
				}
				for (int k=0; k<4; k++)
				{
					char b = (char)(nCurr>>26);
					*szDest++ = s_chBase64EncodingTable[b];
					nCurr <<= 6;
				}
			}
			nWritten+= nLen3*4;

			if ((nFlags & ATL_BASE64_FLAG_NOCRLF)==0)
			{
				*szDest++ = '\r';
				*szDest++ = '\n';
				nWritten+= 2;
			}
		}

		if (nWritten && (nFlags & ATL_BASE64_FLAG_NOCRLF)==0)
		{
			szDest-= 2;
			nWritten -= 2;
		}

		nLen2 = (nSrcLen%3) ? (nSrcLen%3 + 1) : 0;
		if (nLen2)
		{
			int nCurr(0);
			for (int n=0; n<3; n++)
			{
				if (n<(nSrcLen%3))
					nCurr |= *pbSrcData++;
				nCurr <<= 8;
			}
			for (int k=0; k<nLen2; k++)
			{
				byte b = (byte)(nCurr>>26);
				*szDest++ = s_chBase64EncodingTable[b];
				nCurr <<= 6;
			}
			nWritten+= nLen2;
			if ((nFlags & ATL_BASE64_FLAG_NOPAD)==0)
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
		return nWritten;
}

}

int ProxyHelper::Base64Encode(const char *pbSrcData, int nSrcLen, char* szDest,int nDestLen)
{
	return ATL::Base64Encode(pbSrcData,nSrcLen,szDest,&nDestLen,ATL_BASE64_FLAG_NOCRLF);
}

#endif//

}
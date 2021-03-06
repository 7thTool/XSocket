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
#ifndef _H_XPROXY_IMPL_H_
#define _H_XPROXY_IMPL_H_

#include "XSocketImpl.h"
#include "XCodec.h"

namespace XSocket {

/*!
 *	@brief 代理类型.
 *
 *	定义支持的代理类型
 */
enum PROXYTYPE
{
	PROXYTYPE_NONE			= 0,	//!< 不使用代理服务器
	PROXYTYPE_SOCKS4,				//!< 使用SOCKS V4代理
	PROXYTYPE_SOCKS4A,				//!< 使用SOCKS V4A代理
	PROXYTYPE_SOCKS5,				//!< 使用SOCKS V5代理
	PROXYTYPE_HTTP10,				//!< 使用HTTP V1.0代理
	PROXYTYPE_HTTP11,				//!< 使用HTTP V1.1代理
};
// typedef enum {
// 	S_NOSERVICE,
// 	S_PROXY,
// 	S_TCPPM,
// 	S_POP3P,
// 	S_SOCKS4 = 4,	/* =4 */
// 	S_SOCKS5 = 5,	/* =5 */
// 	S_UDPPM,
// 	S_SOCKS,
// 	S_SOCKS45,
// 	S_ADMIN,
// 	S_DNSPR,
// 	S_FTPPR,
// 	S_SMTPP,
// 	S_REVLI,
// 	S_REVCO,
// 	S_ZOMBIE
// }PROXYSERVICE;

/*!
 *	@brief 代理服务信息结构.
 *
 *	定义代理信息结构
 */
typedef struct  tagPROXYINFO
{
	PROXYTYPE eType; 
	char szHost[256];
	u_short nPort;
	bool bAuth;
	char szUser[256];
	char szPwd[256];
}PROXYINFO,*PPROXYINFO;

/*!
 *	@brief 代理状态.
 *
 *	代理过程状态
 */
#define PROXY_STATE_NONE	0		//!< 无
#define PROXY_STATE_OK		7		//!< 代理成功

/*!
 *	@brief ProxySocketT 模板定义.
 *
 *	封装ProxySocketT，实现连接代理
 */
template<class TBase>
class ProxySocketT : public TBase
{
	typedef ProxySocketT<TBase> This;
	typedef TBase Base;
protected:
	byte		m_ProxyState;	//代理状态
	PROXYINFO	m_ProxyInfo;	//代理
	char 		m_szHost[256];	//服务器的地址
	u_short 	m_nPort;		//服务器的端口

public:
	ProxySocketT()
	{
	}

	inline void ResetProxyInfo()
	{
		m_ProxyState = PROXY_STATE_NONE;
		memset(&m_ProxyInfo, 0, sizeof(m_ProxyInfo));
		memset(m_szHost, 0, sizeof(m_szHost));
		m_nPort = 0;
	}

	inline void SetProxyInfo(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy = NULL)
	{
		strcpy(m_szHost, lpszHostAddress);
		m_nPort = nHostPort;
		if(!pProxy || !pProxy->eType) {
			m_ProxyState = PROXY_STATE_OK;
		} else {
			m_ProxyInfo = *pProxy;
			m_ProxyState = 1;
		}
	}

	inline PROXYINFO& GetProxyInfo() 
	{ 
		return m_ProxyInfo; 
	}

	inline const char* GetProxyIp() 
	{ 
		if (IsProxy()) {
			return m_ProxyInfo.szHost;
		}
		ASSERT(0);
		return NULL;
	}
	inline u_short GetProxyPort()
	{ 
		if (IsProxy()) {
			return m_ProxyInfo.nPort;
		}
		ASSERT(0);
		return 0;
	}

	inline const char* GetHostIp() 
	{ 
		return m_szHost;
	}
	inline u_short GetHostPort()
	{ 
		return m_nPort;
	}

	inline PROXYTYPE IsProxy()
	{
		return m_ProxyInfo.eType;
	}

	inline bool IsProxyOK()
	{
		return m_ProxyState==PROXY_STATE_OK;
	}

	inline bool IsInProxy()
	{
		return m_ProxyState!=PROXY_STATE_NONE && m_ProxyState!=PROXY_STATE_OK;
	}

	int Connect(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy = NULL)
	{
		SetProxyInfo(lpszHostAddress, nHostPort, pProxy);
		if (IsProxy()) {
			return Base::Connect(GetProxyIp(), GetProxyPort());
		} else {
			return Base::Connect(GetHostIp(), GetHostPort());
		}
	}

protected:
	//
	int ReceiveProxy(const char* lpBuf, int & nBufLen)
	{
		byte byProxyState = m_ProxyState;
		if (byProxyState%2==1) {
			return 0;
		}

		//组织代理登录协议
		switch(m_ProxyInfo.eType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				byProxyState = PROXY_STATE_NONE;
				if (nBufLen >= 8 && lpBuf[0] == 0x00 && lpBuf[1] == 0x5A) {
					//代理连接成功
					byProxyState = PROXY_STATE_OK;
				}
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				switch (byProxyState) 
				{
				case 2:
					{
						if(nBufLen>0) {
							if (lpBuf[0] == 0x05) {
								byProxyState = 5;
								if(nBufLen>1) {
									if (lpBuf[1] == 0x02) {
										byProxyState = 3;
									}
								}
							}
						}
						if (byProxyState == 2) {
							byProxyState = PROXY_STATE_NONE;
						}
					}
					break;
				case 4:
					{
						if(nBufLen>1) {
							if (lpBuf[0] == 0x05 && lpBuf[1] == 0x00) {
								byProxyState = 5;
							}
						}
						if (byProxyState == 4) {
							byProxyState = PROXY_STATE_NONE;
						}
					}
					break;
				case 6:
					{
						if(nBufLen>1) {
							if (lpBuf[0] == 0x05 && lpBuf[1] == 0x00) {
								byProxyState = PROXY_STATE_OK;
							}
						}
						if (byProxyState != PROXY_STATE_OK) {
							byProxyState = PROXY_STATE_NONE;
						}
					}
					break;
				default:
					break;
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				byProxyState = PROXY_STATE_NONE;
				PRINTF("[%d]\r\n%*s", nBufLen, nBufLen, lpBuf);
				if (strnicmp(lpBuf,"HTTP/",5)==0 && strnicmp(lpBuf+nBufLen-4,("\r\n\r\n"),4)==0) {
					const char* pEnd = strstr(lpBuf, "\r\n");
					if(pEnd) {
						const char* pStart = strstr(lpBuf, " ");
						if (pStart) {
							pStart++;
							if(pStart<pEnd) {
								if (*pStart=='2') {
									byProxyState = PROXY_STATE_OK;
								}
							}
						}
					}
				}
			}
			break;
		}
		if (byProxyState == PROXY_STATE_NONE) {
			return 0;
		}
		m_ProxyState = byProxyState;
		return SOCKET_PACKET_FLAG_COMPLETE;
	}

	int SendProxy()
	{
		char Buf[1024] = {0};
		int nBufLen = 0;

		byte byProxyState = m_ProxyState;
		if (byProxyState%2==0) {
			return 0;
		}

		int ret = 0;
		//组织代理登录协议
		switch(m_ProxyInfo.eType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				byProxyState++;

				const char* lpszHostAddress = m_szHost;
				int nHostAddress = strlen(lpszHostAddress) + 1;

				// SOCKS 4
				// ---------------------------------------------------------------------------
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//# of bytes:   1    1      2              4           variable       1
				Buf[0] = 0x04; // VN: 4
				Buf[1] = (true) ? 0x01 : 0x02; // CD: 1=CONNECT, 2=BIND;
				*(u_short*)&Buf[2] = H2N(m_nPort); // DSTPORT

				nBufLen = 4 + 4 + 1;

				SOCKADDR_IN sockAddr = {0};
				sockAddr.sin_addr.s_addr = inet_addr(lpszHostAddress);
				if (sockAddr.sin_addr.s_addr == INADDR_NONE && m_ProxyInfo.eType == PROXYTYPE_SOCKS4) {
					LPHOSTENT lpHostent = gethostbyname(lpszHostAddress);
					if (lpHostent) {
						sockAddr.sin_addr.s_addr = ((LPIN_ADDR)lpHostent->h_addr)->s_addr;
					}
				}

				if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
					if (m_ProxyInfo.eType == PROXYTYPE_SOCKS4) {
						ret = SOCKET_ERROR;
						Base::SetLastError(ECONNABORTED);
						break;
					} else {
						// For version 4A, if the client cannot resolve the destination host's
						// domain name to find its IP address, it should set the first three bytes
						// of DSTIP to NULL and the last byte to a non-zero value. (This corresponds
						// to IP address 0.0.0.x, with x nonzero.)

						// DSTIP: Set the IP to 0.0.0.x (x is nonzero)
						Buf[4] = 0;
						Buf[5] = 0;
						Buf[6] = 0;
						Buf[7] = 1;

						Buf[8] = 0;	// Terminating NUL-byte for USERID

						// Following the NULL byte terminating USERID, the client must send the 
						// destination domain name and termiantes it with another NULL byte. 

						// Add hostname (including terminating NUL-byte)
						memcpy(&Buf[9], lpszHostAddress, nHostAddress);
						nBufLen += nHostAddress;
					}
				} else {
					*(u_long*)&Buf[4] = sockAddr.sin_addr.s_addr;				// DSTIP
				}
				Buf[nBufLen-1] = 0;

				ret = Base::SendBuf(Buf, nBufLen);
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				// SOCKS 5
				// -------------------------------------------------------------------------------------------
				// The client connects to the server, and sends a version identifier/method selection message:
				//                +----+----------+----------+
				//                |VER | NMETHODS | METHODS  |
				//                +----+----------+----------+
				//                | 1  |    1     | 1 to 255 |
				//                +----+----------+----------+
				//
				// The values currently defined for METHOD are:
				//
				//       o  X'00' NO AUTHENTICATION REQUIRED
				//       o  X'01' GSSAPI
				//       o  X'02' USERNAME/PASSWORD
				//       o  X'03' to X'7F' IANA ASSIGNED
				//       o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
				//       o  X'FF' NO ACCEPTABLE METHODS
				switch (byProxyState) 
				{
				case 1:
					{
						byProxyState++;

						Buf[0] = 0x05;
						Buf[1] = (m_ProxyInfo.bAuth ? 0x02 : 0x01);
						Buf[2] = (m_ProxyInfo.bAuth ? 0x02 : 0x00);
						nBufLen = (m_ProxyInfo.bAuth ? 4 : 3);
						ret = Base::SendBuf(Buf, nBufLen);
					}
					break;
				case 3:
					{
						byProxyState++;

						char nUserLen = (char)strlen(m_ProxyInfo.szUser);
						char nPwdLen = (char)strlen(m_ProxyInfo.szPwd);
						Buf[0] = 0x05;
						Buf[1] = nUserLen;
						nBufLen = 2;
						memcpy(Buf + nBufLen, m_ProxyInfo.szUser, nUserLen);
						nBufLen += nUserLen;
						Buf[nBufLen] = nPwdLen;
						nBufLen += 1;
						memcpy(Buf + nBufLen, m_ProxyInfo.szPwd, nPwdLen);
						nBufLen += nPwdLen;
						ret = Base::SendBuf(Buf, nBufLen);
					}
					break;
				case 5:
					{
						byProxyState++;

						const char* lpszHostAddress = m_szHost;
						int nHostAddress = strlen(lpszHostAddress);
						SOCKADDR_IN sockAddr = {0};
						sockAddr.sin_addr.s_addr = inet_addr(lpszHostAddress);
						if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
							//不用DNS解析，代理服务器会解析
							/*LPHOSTENT lpHostent = gethostbyname(lpszHostAddress);
							if (lpHostent) {
							sockAddr.sin_addr.s_addr = ((LPIN_ADDR)lpHostent->h_addr)->s_addr;
							}*/
						}
						sockAddr.sin_port = H2N(m_nPort);

						Buf[0] = 0x05;
						Buf[1] = 0x01;
						Buf[2] = 0x00;
						Buf[3] = (sockAddr.sin_addr.s_addr!=INADDR_NONE ? 0x01 : 0x03);
						nBufLen = 4;
						if (sockAddr.sin_addr.s_addr != INADDR_NONE) {
							memcpy(Buf + nBufLen, &sockAddr.sin_addr.s_addr, sizeof(sockAddr.sin_addr.s_addr));
							nBufLen += sizeof(sockAddr.sin_addr.s_addr);
						} else {
							Buf[nBufLen] = (char)strlen(lpszHostAddress);
							nBufLen += 1;
							memcpy(Buf + nBufLen, lpszHostAddress, nHostAddress);
							nBufLen += nHostAddress;
						}
						memcpy(Buf + nBufLen, &sockAddr.sin_port, sizeof(sockAddr.sin_port));
						nBufLen += sizeof(sockAddr.sin_port);

						ret = Base::SendBuf(Buf, nBufLen);
					}
					break;
				default:
					break;
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				byProxyState++;

				const char* lpszHostAddress = m_szHost;
				int nHostAddress = strlen(lpszHostAddress);

				sprintf(Buf, "CONNECT %s:%d HTTP/1.%d\r\nHost: %s:%d\r\n",
					lpszHostAddress, m_nPort, /*m_ProxyInfo.nType == PROXYTYPE_HTTP10 ? 0 : */1, lpszHostAddress, m_nPort);

				if (m_ProxyInfo.bAuth)
				{
					char szAuth[1024] = {0};
					char szBase64Encode[1024] = {0};
					//char nNameLen = (char)strlen(m_ProxyInfo.szUser);
					//char nPwdLen = (char)strlen(m_ProxyInfo.szPwd);
					//if (m_ProxyInfo.szPwd[0]) {
						snprintf(szAuth, 1024, "%s:%s", m_ProxyInfo.szUser, m_ProxyInfo.szPwd);
					//} else {
					//	snprintf(szAuth, 1024, "%s", m_ProxyInfo.szUser);
					//}
					int nBase64EncodeLen = 1024;
					Base64Encode((const byte*)szAuth, strlen(szAuth), szBase64Encode, &nBase64EncodeLen);

					strcat(Buf, "Authorization: Basic ");
					strcat(Buf, szBase64Encode);
					strcat(Buf, "\r\n");
					strcat(Buf, "Proxy-Authorization: Basic ");
					strcat(Buf, szBase64Encode);
					strcat(Buf, "\r\n");
				}

				strcat(Buf, "\r\n");

				nBufLen = strlen(Buf);
				ret = Base::SendBuf(Buf, nBufLen);
			}
			break;
		}
		if (ret<0) {
			m_ProxyState = PROXY_STATE_NONE;
		} else {
			m_ProxyState = byProxyState;
		}
		return ret;
	}

	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen) 
	{ 
		if(!IsProxyOK()) {
			int ret = ReceiveProxy(lpBuf, nBufLen);
			if(ret & SOCKET_PACKET_FLAG_COMPLETE) {
				if(!IsProxyOK()) {
					SendProxy();
				}
			}
			return ret;
		}
		return Base::ParseBuf(lpBuf, nBufLen);
	}
	
	void OnConnect(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnConnect(nErrorCode);
			return;
		}
		Base::Select(FD_READ);
		if (!IsProxyOK()) {
			SendProxy();
		} else {
			Base::OnConnect(IsProxyOK()?0:ECONNABORTED);
		}
	}
};

/*!
 *	@brief ProxydSocketT 模板定义.
 *
 *	封装ProxydSocketT，实现代理服务端逻辑
 */
template<class TBase>
class ProxydSocketT : public TBase
{
	typedef ProxydSocketT<TBase> This;
	typedef TBase Base;
protected:
	u_short m_ProxyType:3; //代理类型
	u_short m_ProxyState:3; //代理状态
	u_short m_ProxyFlags:10; //代理标志

public:
	ProxydSocketT():m_ProxyType(PROXYTYPE_NONE),m_ProxyState(PROXY_STATE_NONE),m_ProxyFlags(0)
	{
	}

	inline void SetProxyUserRequired() { m_ProxyFlags |= (1<<0); }
	inline void SetProxyAuthRequired() { m_ProxyFlags |= (1<<1); }
	inline bool IsProxyUserRequired() { return m_ProxyFlags& (1<<0); }
	inline bool IsProxyAuthRequired() { return m_ProxyFlags& (1<<1); }

	inline bool IsProxyOK()
	{
		return m_ProxyType!=PROXYTYPE_NONE && m_ProxyState==PROXY_STATE_OK;
	}

	inline bool IsInProxy()
	{
		return m_ProxyType!=PROXYTYPE_NONE && m_ProxyState!=PROXY_STATE_OK;
	}

	inline int Close()
	{
		int ret = Base::Close();
		m_ProxyType = PROXYTYPE_NONE;
		m_ProxyState = PROXY_STATE_NONE;
		return ret;
	}

protected:
	//
	int ReceiveProxy(const char* lpBuf, int & nBufLen)
	{
		if (m_ProxyType==0) {
			switch(lpBuf[0])
			{
			case 0x04:
			{
#if 1
				char hex[1024] = {0};
				int hexlen = 1024;
				HexEncode((const byte*)lpBuf, nBufLen, hex, &hexlen);
				PRINTF("%.*s", hexlen, hex);
#endif//
				// SOCKS 4
				// ---------------------------------------------------------------------------
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//# of bytes:   1    1      2              4           variable       1
				if(nBufLen < 9) {
					return SOCKET_PACKET_FLAG_PENDING;
				} else {
					//0x01    CONNECT
        			//0x02    BIND
					//byte CD = lpBuf[1];
					u_short port = *(u_short*)&lpBuf[2];
					u_long ip = *(u_long*)&lpBuf[4];
					if(ip != 0) {
						m_ProxyType = PROXYTYPE_SOCKS4;
						OnProxy(ip, port);
						return SOCKET_PACKET_FLAG_COMPLETE;
					} else if(lpBuf[nBufLen-1]==0 /* && lpBuf[4] = 0 && lpBuf[5] = 0 && lpBuf[6] = 0 && lpBuf[7] != 0*/) {
						m_ProxyType = PROXYTYPE_SOCKS4A;
						const char* host = (const char*)(lpBuf+9);
						OnProxy(host, port);
						return SOCKET_PACKET_FLAG_COMPLETE;
					} else {
						return SOCKET_PACKET_FLAG_PENDING;
					}
				}
			}
			break;
			case 0x05:
			{
				m_ProxyType = PROXYTYPE_SOCKS5;
			}
			break;
			default:
			{
				ASSERT(0);
			}
			break;
			}
		}
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  NMETHODS   	METHODS
				//1    1    		1 to 255
#if 1
				char hex[1024] = {0};
				int hexlen = 1024;
				HexEncode((const byte*)lpBuf, nBufLen, hex, &hexlen);
				PRINTF("%.*s", hexlen, hex);
#endif//
				switch (m_ProxyState) 
				{
				case 0:
					{
						if(nBufLen < 3) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						if (IsProxyAuthRequired()) {
							//需要使用用户名密码登录
							m_ProxyState = 2;
							Buf[0] = 0x05;
							Buf[1] = 0x02;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if (IsProxyUserRequired()) {
							//需要使用用户名登录
							m_ProxyState = 1;
							Buf[0] = 0x05;
							Buf[1] = 0xff;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else {
							//不需要使用用户名密码登录
							m_ProxyState = 1;
							Buf[0] = 0x05;
							Buf[1] = 0x00;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						}
					}
					break;
				case 1:
					{
						//VER  CMD  RSV  ATYP DST.ADDR    DST.PROT
						//1    1    1    1    Variable    2
						if(nBufLen < (4 + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						byte ATYP = lpBuf[3];
						if(ATYP == 0x01) { //IPV4
							if(nBufLen < (4 + 4 + 2)) {
								return SOCKET_PACKET_FLAG_PENDING;
							}
							u_long ip = *(u_long*)&lpBuf[4];
							u_short port = *(u_short*)&lpBuf[8];
							OnProxy(ip,port);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if(ATYP == 0X03) { //域名
							int addr_len = lpBuf[4];
							if(nBufLen < (4 + 1 + addr_len + 2)) {
								return SOCKET_PACKET_FLAG_PENDING;
							}
							char* addr = (char*)lpBuf + 4 + 1;
							u_short port = *(u_short*)&lpBuf[4 + addr_len];
							addr[addr_len] = 0;
							OnProxy(addr, port);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if(ATYP == 0X03) { //IPV6
						}
					}
					break;
				case 2:
					{
						if(nBufLen < (1 + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						int user_len = lpBuf[1];
						if(nBufLen < (1 + 1 + user_len + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						const char* user = lpBuf + 1 + 1;
						int pwd_len = lpBuf[1 + 1 + user_len];
						//lpBuf[1 + 1 + user_len] = 0;
						if(nBufLen < (1 + 1 + user_len + 1 + pwd_len + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						const char* pwd = user + user_len + 1;
						//lpBuf[1 + 1 + user_len + 1 + pwd_len] = 0;
						OnProxyAuth(user, user_len, pwd, pwd_len);
						return SOCKET_PACKET_FLAG_COMPLETE;
					}
					break;
				default:
					break;
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				
			}
			break;
		}
		m_ProxyType = PROXYTYPE_NONE;
		m_ProxyState = PROXY_STATE_NONE;
		return 0;
	}

	virtual void OnProxyAuth(const char* user, int user_len, const char* pwd, int pwd_len)
	{

	}
	
	virtual void OnProxyAuthDone(int nErrorCode)
	{
		if(nErrorCode) {
			OnProxyDone(nErrorCode);
			return;
		}
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				ASSERT(0);
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  METHOD
				//1    1
				m_ProxyState = 1;
				Buf[0] = 0x05;
				Buf[1] = 0x00; //
				Base::SendBuf(Buf,2);
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				ASSERT(0);
			}
			break;
		}
	}

	virtual void OnProxy(const char* addr, u_short prot)
	{
		SOCKADDR_IN sock_addr = {0};
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_port = prot;
		sock_addr.sin_addr.s_addr = Ip2N(Url2Ip((char*)(addr)));
		OnProxy(sock_addr);
	}

	inline void OnProxy(u_long ip, u_short port)
	{
		SOCKADDR_IN sock_addr = {0};
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_port = port;
		sock_addr.sin_addr.s_addr = ip;
		OnProxy(sock_addr);
	}

	virtual void OnProxy(const SOCKADDR_IN& addr)
	{
	}
	
	virtual void OnProxyDone(int nErrorCode)
	{
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				//VN  	CD  	DSTPORT	DSTIP                
				//1		1		2		4
				//0x5A    允许转发
				//0x5B    拒绝转发，一般性失败
				//0x5C    拒绝转发，SOCKS 4 Server无法连接到SOCS 4 Client所在主机的
				//		IDENT服务
				//0x5D    拒绝转发，请求报文中的USERID与IDENT服务返回值不相符
				Buf[0] = 0x00;
				if(nErrorCode) {
					Buf[1] = 0x5B;
				} else {
					m_ProxyState = PROXY_STATE_OK;
					Buf[1] = 0x5A;
				}
				//memcpy(Buf + 2, &ProxyAddr_.sin_port, sizeof(ProxyAddr_.sin_port));
				//memcpy(Buf + 2 + 2, &ProxyAddr_.sin_addr.s_addr, sizeof(ProxyAddr_.sin_addr.s_addr));
				Base::SendBuf(Buf,9);
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  REP  RSV   ATYP    DST.ADDR    DST.PROT
				//1    1    1     1       Variable    2
				if(!nErrorCode) {
					m_ProxyState = PROXY_STATE_OK;
					Buf[0] = 0x05; //VER
					Buf[1] = 0x00; //CD
					Buf[2] = 0x00; //RSV
					Buf[3] = 0x01; //ATYP
					//memcpy(Buf + 4, &ProxyAddr_.sin_addr.s_addr, sizeof(ProxyAddr_.sin_addr.s_addr));
					//memcpy(Buf + 4 + 4, &ProxyAddr_.sin_port, sizeof(ProxyAddr_.sin_port));
					Base::SendBuf(Buf,10);
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				ASSERT(0);
			}
			break;
		}
	}

	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen) 
	{ 
		if(!IsProxyOK()) {
			return ReceiveProxy(lpBuf, nBufLen);
		}
		return Base::ParseBuf(lpBuf, nBufLen);
	}
};

}

#endif//_H_XPROXY_IMPL_H_
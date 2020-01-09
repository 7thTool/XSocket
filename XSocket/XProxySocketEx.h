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
#ifndef _H_XPROXYSOCKETEX_H_
#define _H_XPROXYSOCKETEX_H_

#include "XSocketEx.h"
#include "XCodec.h"

namespace XSocket {

/*!
 *	@brief 代理类型.
 *
 *	定义支持的代理类型
 */
#define PROXY_TYPE_NONE		0		//!< 无
#define PROXY_TYPE_CONNECT	1		//!< 连接
#define PROXY_TYPE_BIND		2		//!< 绑定

/*!
 *	@brief 代理状态.
 *
 *	代理过程状态
 */
#define PROXY_STATE_NONE	0		//!< 无
#define PROXY_STATE_OK		0XFF	//!< 代理成功

/*!
 *	@brief ProxyHandler 模板定义.
 *
 *	封装代理过程，实现代理协议
 */
template<class T, byte byProxyType>
class ProxyHandlerT
{
protected:
	byte		m_ProxyState;	//代理状态
	PROXYINFO	m_ProxyInfo;	//代理
	char 		m_szHost[256];	//服务器的地址
	u_short 	m_nPort;		//服务器的端口

public:
	ProxyHandlerT()
	{
		ResetProxyInfo();
	}

	inline void ResetProxyInfo()
	{
		m_ProxyState = PROXY_STATE_NONE;
		memset(&m_ProxyInfo, 0, sizeof(m_ProxyInfo));
		memset(m_szHost, 0, sizeof(m_szHost));
		m_nPort = 0;
	}

	inline void SetProxy(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy = NULL)
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

	inline PROXYINFO& GetProxy() 
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

	inline bool IsConnectProxy()
	{
		return byProxyType==PROXY_TYPE_CONNECT;
	}

	inline bool IsListenProxy()
	{
		return byProxyType==PROXY_TYPE_BIND;
	}

	inline bool IsProxy()
	{
		return m_ProxyInfo.eType!=PROXYTYPE_NONE;
	}

	inline bool IsProxyOK()
	{
		return m_ProxyState==PROXY_STATE_OK;
	}

	inline bool IsInProxy()
	{
		return m_ProxyState!=PROXY_STATE_NONE && m_ProxyState!=PROXY_STATE_OK;
	}

	int ReceiveProxy()
	{
		T* pT = static_cast<T*>(this);
		ASSERT(IsProxy() && IsInProxy());
		if(!IsProxy() || !IsInProxy()) {
			return 0;
		}

		char Buf[1024] = {0};
		int nBufLen = 0;

		byte byProxyState = m_ProxyState;
		if (byProxyState%2==1) {
			return 0;
		}

		int ret = 0;
		//组织代理登录协议
		switch(m_ProxyInfo.eType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				byProxyState = PROXY_STATE_NONE;
				nBufLen = pT->Receive(Buf, sizeof(Buf));
				if (nBufLen >= 8 && Buf[0] == 0x00 && Buf[1] == 0x5A) {
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
						nBufLen = pT->Receive(Buf, sizeof(Buf));
						if(nBufLen>0) {
							byProxyState = 5;
							if (Buf[0] == 0x05) {
								//
							}
							if(nBufLen>1) {
								if (Buf[1] == 0x02) {
									byProxyState = 3;
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
						nBufLen = pT->Receive(Buf, sizeof(Buf));
						if(nBufLen>1) {
							if (Buf[0] == 0x05 && Buf[1] == 0x00) {
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
						nBufLen = pT->Receive(Buf, sizeof(Buf));
						if(nBufLen>1) {
							if (Buf[0] == 0x05 && Buf[1] == 0x00) {
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
				nBufLen = pT->Receive(Buf, sizeof(Buf));
				PRINTF("[%d]\r\n%*s", nBufLen, nBufLen, Buf);
				if (strnicmp(Buf,"HTTP/",5)==0 && strnicmp(Buf+nBufLen-4,("\r\n\r\n"),4)==0) {
					char* pEnd = strstr(Buf, "\r\n");
					if(pEnd) {
						char* pStart = strstr(Buf, " ");
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
			if (nBufLen<0) {
				ret = nBufLen;
			} else {
				ret = SOCKET_ERROR;
				pT->SetLastError(ECONNREFUSED);
			}
		}
		m_ProxyState = byProxyState;
		return ret;
	}

	int SendProxy()
	{
		T* pT = static_cast<T*>(this);
		ASSERT(IsProxy() && IsInProxy());
		if(!IsProxy() || !IsInProxy()) {
			return 0;
		}

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
				int nHostAddress = strlen(lpszHostAddress);

				// SOCKS 4
				// ---------------------------------------------------------------------------
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//# of bytes:   1    1      2              4           variable       1
				Buf[0] = 0x04;													// VN: 4
				Buf[1] = (IsConnectProxy()) ? 0x01 : 0x02;						// CD: 1=CONNECT, 2=BIND;
				*(u_short*)&Buf[2] = H2N(m_nPort);							// DSTPORT

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
						pT->SetLastError(ECONNABORTED);
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

				ret = pT->Send(Buf, nBufLen);
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
						ret = pT->Send(Buf, nBufLen);
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
						ret = pT->Send(Buf, nBufLen);
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

						ret = pT->Send(Buf, nBufLen);
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
					Base64Encode(szAuth, strlen(szAuth), szBase64Encode, 1024);

					strcat(Buf, "Authorization: Basic ");
					strcat(Buf, szBase64Encode);
					strcat(Buf, "\r\n");
					strcat(Buf, "Proxy-Authorization: Basic ");
					strcat(Buf, szBase64Encode);
					strcat(Buf, "\r\n");
				}

				strcat(Buf, "\r\n");

				nBufLen = strlen(Buf);
				ret = pT->Send(Buf, nBufLen);
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

	/*!
	 *	@brief 阻塞同步代理过程.
	 *
	 *	代理过程需要使用者保证阻塞IO.
	 */
	int ConnectProxy()
	{
		T* pT = static_cast<T*>(this);

		int ret = 0;
		if (!IsInProxy()) {
			return ret;
		}

		do {
			ret = SendProxy();
			if (ret<0) {
				break;
			}
			ret = ReceiveProxy();
			if (ret<0) {
				break;
			}
		} while (IsInProxy());

		return ret;
	}
};

/*!
 *	@brief ProxyConnectHandler 模板定义.
 *
 *	封装ProxyConnectHandler，实现连接代理
 */
template<class TBase = SocketEx>
class ProxyConnectHandler 
	: public TBase
	, public ProxyHandlerT<ProxyConnectHandler<TBase>,PROXY_TYPE_CONNECT>
{
	typedef ProxyConnectHandler<TBase> This;
	typedef TBase Base;
	typedef ProxyHandlerT<ProxyConnectHandler<TBase>,PROXY_TYPE_CONNECT> ProxyHandler;
public:
	ProxyConnectHandler():Base()
	{

	}

	int Close()
	{
		int rlt = Base::Close();
		ProxyHandler::ResetProxyInfo();
		return rlt;
	}

	int Connect(const char* lpszHostAddress, unsigned short nHostPort, PPROXYINFO pProxy = NULL)
	{
		ProxyHandler::SetProxy(lpszHostAddress, nHostPort, pProxy);
		if (ProxyHandler::IsProxy())
		{
			return Base::Connect(ProxyHandler::GetProxyIp(), ProxyHandler::GetProxyPort());
		}
		else
		{
			return Base::Connect(ProxyHandler::GetHostIp(), ProxyHandler::GetHostPort());
		}
	}

protected:
	void OnReceive(int nErrorCode)
	{
		if (ProxyHandler::IsInProxy()) {
			if (nErrorCode) {
				Base::OnConnect(nErrorCode);
			} else {
				ProxyHandler::ReceiveProxy();
				//
				if (!ProxyHandler::IsInProxy()) {
					Base::OnConnect(ProxyHandler::IsProxyOK()?0:ECONNABORTED);
				}
			}
		} else {
			Base::OnReceive(ProxyHandler::IsProxyOK()?nErrorCode:ECONNABORTED);
		}
	}
	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags)
	{
		Base::OnReceive(lpBuf, nBufLen, nFlags);
	}
	
	void OnSend(int nErrorCode)
	{
		if (ProxyHandler::IsInProxy()) {
			if (nErrorCode) {
				Base::OnConnect(nErrorCode);
			} else {
				ProxyHandler::SendProxy();
			}
		} else {
			Base::OnSend(ProxyHandler::IsProxyOK()?nErrorCode:ECONNABORTED);
		}
	}
	
	void OnConnect(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnConnect(nErrorCode);
			return;
		}

		Base::AddSelect(FD_READ|FD_WRITE);
		if (ProxyHandler::IsInProxy()) {
		} else {
			Base::OnConnect(ProxyHandler::IsProxyOK()?0:ECONNABORTED);
		}
	}
};

}

#endif//_H_XPROXYSOCKETEX_H_
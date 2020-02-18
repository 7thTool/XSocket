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
#ifndef _H_XSOCKETIMPL_H_
#define _H_XSOCKETIMPL_H_

#include "XSocketEx.h"

#include <string>
#include <queue>
#include <list>
#include <map>
using namespace std;

namespace XSocket {

/*!
 *	@brief 网络数据包标志 定义.
 *
 *	定义支持的网络数据包标志
 *  兼容send/recv flags 标志
 */
enum  
{
	SOCKET_PACKET_FLAG_NONE			= 0,			//未知
	//MSG_DONTROUTE,
	//MSG_PARTIAL,
	//...
	SOCKET_PACKET_MSG_MASK			= 0X0000FFFF,
	//bitflag
	SOCKET_PACKET_FLAG_PENDING		= 0X00010000,	//未完成
	SOCKET_PACKET_FLAG_COMPLETE		= 0X00020000,	//是完整的包
	SOCKET_PACKET_FLAG_SEND			= 0X00040000,	//是发送包
	SOCKET_PACKET_FLAG_RECEIVE		= 0X00080000,	//是接收包
	SOCKET_PACKET_FLAG_PUSH			= 0X00100000,	//是推送包
	SOCKET_PACKET_FLAG_RESPONSE		= 0X00200000,	//是发送包的回应包
	SOCKET_PACKET_FLAG_FINAL		= 0X00400000,	//是还要继续收发包
	SOCKET_PACKET_FLAG_TEMPBUF		= 0X08000000,	//临时内存，不能引用buf指针
	SOCKET_PACKET_FLAG_MASK			= 0X0FFF0000,
	//opcodes
	SOCKET_PACKET_OP_CONTINUE 		= 0X00000000,	//是继续收发包
	SOCKET_PACKET_OP_HEARTBEAT		= 0X10000000,	//是心跳包
	SOCKET_PACKET_OP_PING			= SOCKET_PACKET_OP_HEARTBEAT,	//是PING
	SOCKET_PACKET_OP_PONG			= 0X20000000,	//是PONG
	SOCKET_PACKET_OP_CLOSE			= 0X30000000,	//关闭
	SOCKET_PACKET_OP_TEXT			= 0X40000000,	//文本
    SOCKET_PACKET_OP_BINARY 		= 0x50000000,	//二进制
	SOCKET_PACKET_OP_MASK			= 0XF0000000,
};

/*!
 *	@brief TcpSocket 定义.
 *
 *	封装SocketEx，定义对称的发送/接收（写入/读取）网络架构
 */
template<class TBase = SocketEx>
class TcpSocket : public TBase
{
	typedef TBase Base;
protected:
	int m_nRecvLen;
	char* m_pRecvBuf;
	int m_nRecvBufLen;
	int m_nSendLen;
	const char* m_pSendBuf;
	int m_nSendBufLen;
public:
	TcpSocket()
		:Base()
		,m_nRecvLen(0)
		,m_pRecvBuf(nullptr)
		,m_nRecvBufLen(0)
		,m_nSendLen(0)
		,m_pSendBuf(nullptr)
		,m_nSendBufLen(0)
	{
		
	}

	virtual ~TcpSocket()
	{

	}

	inline int Close()
	{
		int ret = Base::Close();
		m_nRecvLen = 0;
		m_pRecvBuf = nullptr;
		m_nRecvBufLen = 0;
		m_nSendLen = 0;
		m_pSendBuf = nullptr;
		m_nSendBufLen = 0;
		return ret;
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen) { return SOCKET_PACKET_FLAG_COMPLETE; }

	//准备接收缓存
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen)
	{
		return false;
	}
	//准备扩展接收缓存
	virtual bool PrepareExpandRecvBuf(char* & lpBuf, int & nBufLen)
	{
		return false;
	}

	//接收完整一个包
	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags) 
	{
		
	}

	//准备发送数据包
	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
	{
		return false;
	}

	//发送完整一个包
	virtual void OnSendBuf(const char* lpBuf, int nBufLen)
	{

	}

protected:
	//
	virtual void OnReceive(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnReceive(nErrorCode);
			return;
		}
		bool bConitnue = false;
		do {
			bConitnue = false;
			char* lpBuf = nullptr;
			int nBufLen = 0;
			if (!m_pRecvBuf) {
				if(!PrepareRecvBuf(lpBuf,nBufLen)) {
					//说明没有可接收缓存
					return;
				}
				m_nRecvLen = 0;
				m_pRecvBuf = lpBuf;
				m_nRecvBufLen = nBufLen;
			}
			lpBuf = m_pRecvBuf+m_nRecvLen;
			nBufLen = (int)(m_nRecvBufLen-m_nRecvLen);
			ASSERT(nBufLen>0);
			nBufLen = Base::Receive(lpBuf,nBufLen);
			if (nBufLen<0) {
				Base::OnReceive(XSocket::Socket::GetLastError());
			} else if(nBufLen == 0) {
				Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
			} else {
				OnReceive(lpBuf, nBufLen, 0);
				bConitnue = Base::IsSocket();
			}
		} while (bConitnue);
	}

	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags) 
	{
		Base::OnReceive(lpBuf, nBufLen, nFlags);
		m_nRecvLen += nBufLen;
		const char* lpParseBuf = m_pRecvBuf;
		int nParseBufLen = m_nRecvLen; //还剩多少数据长度需要解析
		int nParseFlags = 0;
		do {
			int nPacketBufLen = nParseBufLen;
			nParseFlags = ParseBuf(lpParseBuf, nPacketBufLen);
			if(!nParseFlags) {
				Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
				break;
			} else if(!(nParseFlags & SOCKET_PACKET_FLAG_COMPLETE)) {
				break;
			} else {
				OnRecvBuf(lpParseBuf, nPacketBufLen, nParseFlags);
			}
			lpParseBuf += nPacketBufLen;
			nParseBufLen -= nPacketBufLen;
		} while (nParseBufLen > 0);
		if(!nParseFlags) {
			//异常不处理了，后续会关闭连接
		} else {
			if(nParseBufLen <= 0) {
				m_nRecvLen = 0;
				//m_pRecvBuf;
				//m_nRecvBufLen;
			} else if(nParseBufLen < m_nRecvBufLen) {
				//还剩nParseBufLen长度数据没有解析
				if(nParseBufLen == m_nRecvLen) {
					//没有解析任何数据，不需要移动数据
				} else {
					//需要移动数据
					m_nRecvLen = nParseBufLen;
					memmove(m_pRecvBuf, lpParseBuf, nParseBufLen);
				}
			} else {
				//需要扩展接收缓存
				PrepareExpandRecvBuf(m_pRecvBuf, m_nRecvBufLen);
			}
		}
	}

	virtual void OnSend(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnSend(nErrorCode);
			return;
		}

		bool bConitnue = false;
		do {
			bConitnue = false;
			const char* lpBuf = nullptr;
			int nBufLen = 0;
			if (!m_pSendBuf) {
				if(!PrepareSendBuf(lpBuf,nBufLen)) {
					//说明没有可发送数据
					Base::RemoveSelect(FD_WRITE);
					return;
				}
				m_nSendLen = 0;
				m_pSendBuf = lpBuf;
				m_nSendBufLen = nBufLen;
			}
			lpBuf = m_pSendBuf+m_nSendLen;
			nBufLen = (int)(m_nSendBufLen-m_nSendLen);
			ASSERT(lpBuf && nBufLen>0);
			nBufLen = Base::Send(lpBuf,nBufLen);
			if (nBufLen<0) {
				Base::OnSend(XSocket::Socket::GetLastError());
			} else if(nBufLen == 0) {
				Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
			} else {
				OnSend(lpBuf, nBufLen, 0);
				bConitnue = Base::IsSocket(); //继续发送
			}
		} while (bConitnue);
	}

	virtual void OnSend(const char* lpBuf, int nBufLen, int nFlags)
	{
		Base::OnSend(lpBuf, nBufLen, nFlags);
		m_nSendLen += nBufLen;
		if (m_nSendLen >= m_nSendBufLen) {
			OnSendBuf(m_pSendBuf, m_nSendLen);
			m_nSendLen = 0;
			m_pSendBuf = nullptr;
			m_nSendBufLen = 0;
		}
	}
};

/*!
 *	@brief SimpleSocketT 定义.
 *
 *	封装SimpleSocketT，实现简单的流式发送/接收（写入/读取）网络架构
 */
template<class TBase, u_short uMaxBufSize = 8*1024>
class SimpleSocketT : public TcpSocket<TBase>
{
	typedef TcpSocket<TBase> Base;
protected:
	typedef std::string SimpleBuffer;
	SimpleBuffer m_RecvBuffer;
	SimpleBuffer m_SendBuffer;
	SimpleBuffer m_PrepareSendBuffer;
	//std::mutex m_SendSection;
	//std::mutex m_RecvSection;

public:
	SimpleSocketT()
	{
		m_RecvBuffer.reserve(uMaxBufSize);
		m_RecvBuffer.resize(uMaxBufSize);
		m_SendBuffer.reserve(uMaxBufSize);
		m_PrepareSendBuffer.reserve(uMaxBufSize);
	}

	virtual ~SimpleSocketT()
	{
		
	}

	inline int Close()
	{
		int ret = Base::Close();
		//std::unique_lock<std::mutex> lock(m_SendSection);

		m_PrepareSendBuffer.clear();
		m_SendBuffer.clear();
		//lock.unlock();
		return ret;
	}

	inline size_t NotSendBufSize() 
	{
		return m_SendBuffer.size() + m_PrepareSendBuffer.size();
	}

	inline std::string& SendBuf() 
	{
		return m_SendBuffer;
	}

	inline int SendBuf(const std::string& Buf, int nFlags = 0)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);
		
		m_SendBuffer += Buf;

		return SendBufDirect(nFlags);
	}

	inline int SendBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);

		m_SendBuffer.append(lpBuf,lpBuf+nBufLen);

		return SendBufDirect(nFlags);
	}

	inline int SendBufDirect(int nFlags = 0)
	{
		ASSERT(Base::IsSocket());
		int nBufLen = m_SendBuffer.size();
		if(!Base::IsSelect(FD_WRITE)) {
			Base::Select(FD_WRITE);
		}
		return nBufLen;
	}

// 	int RecvBuf(char* lpBuf, int nBufLen, int* nFlags = nullptr)
// 	{
// 		std::lock_guard<std::mutex> lock(m_RecvSection);
// 		ASSERT(nFlags);
// 		int nRecvBufLen = m_RecvBuffer.size();
// 		if (nRecvBufLen>0) {
// 			if (!(*nFlags)) {
// 				*nFlags = ParseBuf(&m_RecvBuffer[0],nRecvBufLen);
// 				if ((*nFlags)&SOCKET_PACKET_FLAG_COMPLETE) {
// 					if (nRecvBufLen<=nBufLen) {
// 						memcpy(lpBuf,&m_RecvBuffer[0],nRecvBufLen);
// 						m_RecvBuffer.erase(m_RecvBuffer.begin(),m_RecvBuffer.begin()+nRecvBufLen);
// 					}
// 					return nRecvBufLen;
// 				}
// 			} else {
// 				if (nBufLen>=nRecvBufLen) {
// 					nBufLen = nRecvBufLen;
// 				}
// 				if (nBufLen>0) {
// 					memcpy(lpBuf,&m_RecvBuffer[0],nBufLen);
// 					m_RecvBuffer.erase(m_RecvBuffer.begin(),m_RecvBuffer.begin()+nBufLen);
// 				}
// 				return nBufLen;
// 			}
// 		}
// 		return 0;
// 	}

// 	void Dispatch()
// 	{
// 		int nFlags = 0;
// 		do
// 		{
// 			int nBufLen = Receive(nullptr,0,&nFlags);
// 			if (!(nFlags&SOCKET_PACKET_FLAG_COMPLETE)) {
// 				break;
// 			}
// 			string Buf(nBufLen,0);
// 			char* lpBuf = (char*)Buf.c_str();
// 			nBufLen = Receive(lpBuf,nBufLen,&nFlags);
// 			if (nFlags&SOCKET_PACKET_FLAG_RESPONSE) {
// 				OnResponse(lpBuf,nBufLen,nFlags);
// 			} else {
// 				OnPush(lpBuf,nBufLen,nFlags);
// 			}
// 		} while(true);
// 	}

// protected:
// 	//Dispatch 实现接口 
// 	virtual void OnResponse(const char* lpBuf, int nBufLen, int nFlags)
// 	{

// 	}

// 	virtual void OnPush(const char* lpBuf, int nBufLen, int nFlags)
// 	{

// 	}

protected:
	//TcpSocket 实现接口
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen)
	{
		//std::lock_guard<std::mutex> lock(m_RecvSection);

		lpBuf = &m_RecvBuffer[0];
		nBufLen = m_RecvBuffer.size();

		return true;
	}
	virtual bool PrepareExpandRecvBuf(char* & lpBuf, int & nBufLen)
	{
		//std::lock_guard<std::mutex> lock(m_RecvSection);

		m_RecvBuffer.resize(m_RecvBuffer.size() + uMaxBufSize);
		lpBuf = &m_RecvBuffer[0];
		nBufLen = m_RecvBuffer.size();
		return true;
	}

	// virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags) 
	// {
	// 	Base::OnRecvBuf(lpBuf, nBufLen, nFlags);

	// 	// std::lock_guard<std::mutex> lock(m_RecvSection);

	// 	// m_RecvBuffer.insert(m_RecvBuffer.end(),lpBuf,lpBuf+nBufLen);
	// }

	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
	{
		//std::unique_lock<std::mutex> lock(m_SendSection);

		int nSendBufLen = m_SendBuffer.size();
		if (nSendBufLen>0) {
			m_PrepareSendBuffer.swap(m_SendBuffer);
			m_SendBuffer.clear();
			lpBuf = m_PrepareSendBuffer.c_str();
			nBufLen = m_PrepareSendBuffer.size();
			//lock.unlock();
			return true;
		}

		return false;
	}

	virtual void OnSendBuf(const char* lpBuf, int nBufLen) 
	{
		Base::OnSendBuf(lpBuf, nBufLen);
	}
};

// /*!
//  *	@brief SocketArchitectureT 定义.
//  *
//  *	封装SocketArchitectureT，实现块状的数据包式的发送/接收（写入/读取）网络架构
//  */
// template<class TBase, u_short uMaxBufSize = 1024>
// class SocketArchitectureT : public TBase
// {
// 	typedef TBase Base;
// protected:
// 	typedef struct tagSABuf
// 	{
// 		int nSendBufLen;
// 		const char* pSendBuf;
// 		int nSendFlags;
// 		int nRecvLen;
// 		char RecvBuf[uMaxBufSize];
// 		int nRecvFlags;
// 	}SABUF,*PSABUF;
// 	typedef std::queue<SABUF> PACKList;
// 	PACKList m_RecvPackList;
// 	PACKList m_SendPackList;
// 	std::mutex m_SendSection;
// 	std::mutex m_RecvSection;

// public:
// 	SocketArchitectureT()
// 	{
		
// 	}

// 	virtual ~SocketArchitectureT()
// 	{
		
// 	}

	// inline int Close()
	// {
	// 	int ret = Base::Close();
			
	// 	std::unique_lock<std::mutex> LockSend(m_SendSection);
	// 	while (!m_SendPackList.empty())
	// 	{
	// 		SABUF & saBuf = m_SendPackList.front();
	// 		if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
	// 			delete []saBuf.pSendBuf;
	// 		}
	// 		m_SendPackList.pop();
	// 	}
	// 	LockSend.unlock();

	// 	std::unique_lock<std::mutex> LockRecv(m_RecvSection);
	// 	while (!m_RecvPackList.empty())
	// 	{
	// 		SABUF & saBuf = m_RecvPackList.front();
	// 		if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
	// 			delete []saBuf.pSendBuf;
	// 		}
	// 		m_RecvPackList.pop();
	// 	}
	// 	LockRecv.unlock();
	// 	return ret;
	// }

// 	int Send(const char* lpBuf, int nBufLen, int nFlags = 0)
// 	{
// 		std::unique_lock<std::mutex> lock(m_SendSection);

// 		SABUF saZero = {0};
// 		m_SendPackList.push(saZero);
// 		SABUF & saBuf = m_SendPackList.back();
// 		if (nFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
// 			char* pTempBuf = new char[nBufLen+1];
// 			memcpy(pTempBuf,lpBuf,nBufLen);
// 			pTempBuf[nBufLen] = 0;
// 			saBuf.pSendBuf = pTempBuf;
// 		} else {
// 			saBuf.pSendBuf = lpBuf;
// 		}
// 		saBuf.nSendBufLen = nBufLen;
// 		saBuf.nSendFlags = nFlags;
// 		return nBufLen;
// 	}

// 	int Receive(char* lpBuf, int nBufLen = uMaxBufSize, int* nFlags = nullptr)
// 	{
// 		std::unique_lock<std::mutex> lock(m_RecvSection);

// 		if (!m_RecvPackList.empty()) {
// 			SABUF & saBuf = m_RecvPackList.front();
// 			if (nFlags) {
// 				*nFlags = saBuf.nRecvFlags;
// 			}
// 			if (saBuf.nRecvFlags&SOCKET_PACKET_FLAG_COMPLETE) {
// 				if (nBufLen>=saBuf.nRecvLen) {
// 					memcpy(lpBuf,saBuf.RecvBuf,saBuf.nRecvLen);
// 					m_RecvPackList.pop();
// 				}
// 				return saBuf.nRecvLen;
// 			}
// 		}
// 		return 0;
// 	}

// 	void Dispatch()
// 	{
// 		char lpBuf[uMaxBufSize];
// 		int nBufLen = uMaxBufSize;
// 		int nFlags = 0;
// 		while ((nBufLen=Receive(lpBuf,nBufLen,&nFlags))>0)
// 		{
// 			if (nFlags&SOCKET_PACKET_FLAG_RESPONSE) {
// 				OnResponse(lpBuf,nBufLen,nFlags);
// 			} else {
// 				OnPush(lpBuf,nBufLen,nFlags);
// 			}
// 		}
// 	}

// protected:
// 	//Dispatch 实现接口 
// 	virtual void OnResponse(const char* lpBuf, int nBufLen, int nFlags)
// 	{

// 	}

// 	virtual void OnPush(const char* lpBuf, int nBufLen, int nFlags)
// 	{

// 	}

// protected:
// 	//TcpSocket 实现接口
// 	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen)
// 	{
// 		SABUF saZero = {0};
// 		m_RecvPackList.push(saZero);
// 		SABUF & saBuf = m_RecvPackList.back();
// 		lpBuf = saBuf.RecvBuf;
// 		nBufLen = uMaxBufSize;
// 		return true;
// 	}

// 	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags) 
// 	{
// 		Base::OnReceive(lpBuf, nBufLen, nFlags);

// 		std::unique_lock<std::mutex> lock(m_RecvSection);

// 		ASSERT (lpBuf && nBufLen);
// 		SABUF & saBuf = m_RecvPackList.back();
// 		ASSERT(saBuf.RecvBuf==lpBuf);
// 		saBuf.nRecvLen = nBufLen;
// 		saBuf.nRecvFlags = nFlags;
// 	}

// 	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
// 	{
// 		std::unique_lock<std::mutex> lock(m_SendSection);

// 		if (!m_SendPackList.empty()) {
// 			SABUF & saBuf = m_SendPackList.front();
// 			lpBuf = saBuf.pSendBuf;
// 			nBufLen = saBuf.nSendBufLen;
// 			return true;
// 		}
// 		return false;
// 	}

// 	virtual void OnSend(const char* lpBuf, int nBufLen) 
// 	{
// 		Base::OnSend(lpBuf, nBufLen);

// 		std::unique_lock<std::mutex> lock(m_SendSection);

// 		ASSERT (lpBuf && nBufLen);
// 		SABUF & saBuf = m_SendPackList.front();
// 		ASSERT(saBuf.pSendBuf==lpBuf && saBuf.nSendBufLen==nBufLen);
// 		if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
// 			delete []saBuf.pSendBuf;
// 		}
// 		m_SendPackList.pop();
// 	}
// };

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief UdpSocket 定义.
 *
 *	封装UdpSocket，定义Udp套接字实现接口
 */
template<class TBase = SocketEx, class TSockAddr = SOCKADDR_IN>
class UdpSocket : public TBase
{
	typedef TBase Base;
public:
	typedef TSockAddr SockAddr;
protected:
	int m_nSendLen;
	const char* m_pSendBuf;
	int m_nSendBufLen;
	const SockAddr* m_pSendAddr;
public:
	UdpSocket()
		:Base()
		,m_nSendLen(0)
		,m_pSendBuf(nullptr)
		,m_nSendBufLen(0)
		,m_pSendAddr(nullptr)
	{

	}

	virtual ~UdpSocket()
	{

	}

	inline int Close()
	{
		int ret = Base::Close();
		m_nSendLen = 0;
		m_pSendBuf = nullptr;
		m_nSendBufLen = 0;
		m_pSendAddr = nullptr;
		return ret;
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen, const SockAddr & stAddr) { return SOCKET_PACKET_FLAG_COMPLETE; }

	//准备接收缓存
	// virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen, SockAddr* & lpAddr)
	// {
	// 	return false;
	// }

	//接收完整一个包
	virtual void OnRecvBuf(const char* lpBuf, int nBufLen, const SockAddr & stAddr)
	{

	}

	//准备发送数据包
	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen, const SockAddr* & lpAddr)
	{
		return false;
	}

	//发送完整一个包
	virtual void OnSendBuf(const char* lpBuf, int nBufLen, const SockAddr & stAddr)
	{

	}

protected:
	//
	virtual void OnReceive(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnReceive(nErrorCode);
			return;
		}

		bool bConitnue = false;
		do {
			bConitnue = false;
			//UDP 保证一次接收一个完整UDP包
			char lpBuf[1025] = {0};
			int nBufLen = 1024;
			SockAddr stAddr;
			int nAddrLen = sizeof(SockAddr);
			nBufLen = Base::ReceiveFrom(lpBuf,nBufLen,(SOCKADDR*)&stAddr,&nAddrLen);
			if (nBufLen<0) {
				Base::OnReceive(XSocket::Socket::GetLastError());
			} else if(nBufLen == 0) {
				Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
			} else {
				Base::Trigger(FD_READ, lpBuf, nBufLen,(const SOCKADDR*)&stAddr, nAddrLen, 0);
				bConitnue = Base::IsSocket();
			}
		} while(bConitnue);
	}

	virtual void OnReceiveFrom(const char* lpBuf, int nBufLen, const SOCKADDR* lpAddr, int nAddrLen, int nFlags)
	{
		ASSERT(nAddrLen==sizeof(SockAddr));
		Base::OnReceiveFrom(lpBuf, nBufLen, lpAddr, nAddrLen, nFlags); 
		const char* lpParseBuf = lpBuf;
		int nParseBufLen = nBufLen; //还剩多少数据长度需要解析
		do {
			int nPacketBufLen = nParseBufLen;
			int nParseFlags = ParseBuf(lpParseBuf, nPacketBufLen, *(SockAddr*)lpAddr);
			if(!(nParseFlags & SOCKET_PACKET_FLAG_COMPLETE)) {
				//UDP不允许存在解包不完整，不完整就丢弃
				//Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
				break;
			}
			OnRecvBuf(lpParseBuf, nPacketBufLen, *(SockAddr*)lpAddr);
			lpParseBuf += nPacketBufLen;
			nParseBufLen -= nPacketBufLen;
		} while (nParseBufLen > 0);
	}

	virtual void OnSend(int nErrorCode)
	{
		if (nErrorCode) {
			Base::OnSend(nErrorCode);
			return;
		}
		bool bConitnue = false;
		do {
			bConitnue = false;
			const char* lpBuf = nullptr;
			int nBufLen = 0;
			const SockAddr* lpAddr;
			if (!m_pSendBuf) {
				if(!PrepareSendBuf(lpBuf,nBufLen,lpAddr)) {
					//说明没有可发送数据
					return;
				}
				m_nSendLen = 0;
				m_pSendBuf = lpBuf;
				m_nSendBufLen = nBufLen;
				m_pSendAddr = lpAddr;
			}
			ASSERT(m_nSendLen == 0);
			lpBuf = m_pSendBuf+m_nSendLen;
			nBufLen = (int)(m_nSendBufLen-m_nSendLen);
			lpAddr = m_pSendAddr;
			ASSERT(lpBuf && nBufLen>0);
			nBufLen = Base::SendTo(lpBuf,nBufLen,(const SOCKADDR*)lpAddr,sizeof(SockAddr));
			if (nBufLen<0) {
				Base::OnSend(XSocket::Socket::GetLastError());
			} else if(nBufLen == 0) {
				Base::Trigger(FD_CLOSE, XSocket::Socket::GetLastError());
			} else {
				Base::Trigger(FD_WRITE, lpBuf, nBufLen, (const SOCKADDR*)lpAddr, sizeof(SockAddr), 0);
				bConitnue = Base::IsSocket(); //继续发送
			}
		} while(bConitnue);
	}
	
	virtual void OnSendTo(const char* lpBuf, int nBufLen, const SOCKADDR* lpAddr, int nAddrLen, int nFlags)
	{
		ASSERT(nAddrLen==sizeof(SockAddr));
		Base::OnSendTo(lpBuf, nBufLen, lpAddr, nAddrLen, nFlags);
		m_nSendLen += nBufLen;
		if (m_nSendLen >= m_nSendBufLen) {
			OnSendBuf(m_pSendBuf, m_nSendLen, *(SockAddr*)lpAddr);
			m_nSendLen = 0;
			m_pSendBuf = nullptr;
			m_nSendBufLen = 0;
			m_pSendAddr = nullptr;
		} else {
			ASSERT(0); //UDP 不应该发送太大的包导致发不完，建议520字节包
		}
	}
};

/*!
 *	@brief SimpleUdpSocketT 定义.
 *
 *	封装SimpleUdpSocketT，实现简单的Udp数据包网络架构
 */
template<class TBase, class TSockAddr = SOCKADDR_IN>
class SimpleUdpSocketT : public UdpSocket<TBase,TSockAddr>
{
	typedef UdpSocket<TBase,TSockAddr> Base;
public:
	typedef TSockAddr SockAddr;
protected:
	typedef struct tagSABuf
	{
		const char* pSendBuf;
		int nSendBufLen;
		SockAddr SendAddr;
		int nSendFlags;
	}SABUF,*PSABUF;
	std::deque<SABUF> SendBuffers_;

public:
	SimpleUdpSocketT()
	{
		//SendBuffers_.reserve(256);
	}

	virtual ~SimpleUdpSocketT()
	{
		
	}

	inline int Close()
	{
		int ret = Base::Close();

		for(auto& buffer : SendBuffers_)
		{
			if(buffer.nSendFlags & SOCKET_PACKET_FLAG_TEMPBUF) {
				delete []buffer.pSendBuf;
			}
		}
		SendBuffers_.clear();

		return ret;
	}

	int SendBuf(const char* lpBuf, int nBufLen, const SockAddr & stAddr, int nFlags = 0)
	{
		ASSERT(Base::IsSocket());
		SABUF buffer = {0};
		if(nFlags & SOCKET_PACKET_FLAG_TEMPBUF) {
			char* pNewBuf = new char[nBufLen];
			memcpy(pNewBuf, lpBuf, nBufLen);
			buffer.pSendBuf = pNewBuf;
		} else {
			buffer.pSendBuf = lpBuf;
		}
		buffer.nSendBufLen = nBufLen;
		buffer.SendAddr = stAddr;
		buffer.nSendFlags = nFlags;
		SendBuffers_.push_back(buffer);
		if(!Base::IsSelect(FD_WRITE)) {
			Base::Select(FD_WRITE);
		}
		return nBufLen;
	}

protected:
	//
	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen, const SockAddr* & lpAddr)
	{
		if (!SendBuffers_.empty()) {
			auto& buffer = SendBuffers_.front();
			lpBuf = buffer.pSendBuf;
			nBufLen = buffer.nSendBufLen;
			lpAddr = &buffer.SendAddr;
			return true;
		}
		return false;
	}

	virtual void OnSendBuf(const char* lpBuf, int nBufLen, const SockAddr & stAddr) 
	{
		Base::OnSendBuf(lpBuf, nBufLen, stAddr);
		auto& buffer = SendBuffers_.front();
		if(buffer.nSendFlags & SOCKET_PACKET_FLAG_TEMPBUF) {
			delete []buffer.pSendBuf;
		}
		SendBuffers_.pop_front();
	}
};


/*!
 *	@brief StableUdpSocketT 定义.
 *
 *	封装StableUdpSocketT，定义基于UDP的稳定可靠传输的网络架构
 *  
 *  实现类似于TCP协议的超时重传，有序接受，应答确认，滑动窗口流量控制等机制，
 *	使用UDP数据包+序列号，UDP数据包+时间戳，应答确认机制。
 *	|8字节首部|最大512长度内容|=520字节。
 */
//template<class TBase, class SockAddr = SOCKADDR_IN>
//class StableUdpSocketT : public SimpleUdpSocketT<TBase,SockAddr>
//{
//	typedef SimpleUdpSocketT<TBase,SockAddr> Base;
//protected:
//	enum
//	{
//		stable_udp_flag_seq		= 0x01,	//序号
//		stable_udp_flag_ack		= 0x02, //序号确认
//		stable_udp_flag_retry	= 0x04,	//序号重试
//		//stable_udp_flag_seq 发送序号
//		//stable_udp_flag_ack 确认序号
//		//stable_udp_flag_seq|stable_udp_flag_retry 重发序号
//		//stable_udp_flag_ack|stable_udp_flag_retry 请求重发序号
//	};
//	struct udpheader 
//	{
//		unsigned int ver:8;
//		unsigned int seq:8;
//		unsigned int crc:16;
//		unsigned int flags:6;
//		unsigned int cap:16;
//		unsigned int len:10;
//	};
//public:
//	StableUdpSocketT()
//		:Base()
//	{
//
//	}
//
//	virtual ~StableUdpSocketT()
//	{
//
//	}
//
//	inline int Close()
//	{
//		int rlt = Base::Close();
//		return rlt;
//	}
//
//protected:
//	//
//
//protected:
//	//
//	virtual void OnReceive(int nErrorCode)
//	{
//		Base::OnReceive(nErrorCode);
//	}
//
//	virtual void OnSend(int nErrorCode)
//	{
//		Base::OnSend(nErrorCode);
//	}
//};


/*!
 *	@brief SimpleSvrSocketT 定义.
 *
 *	封装SimpleSvrSocketT，增加服务对象，实现简单的流式发送/接收（写入/读取）网络架构
 */
template<class TBase>
class SimpleSvrSocketT : public TBase
{
	typedef TBase Base;
public:
	typedef typename Base::SocketSet SocketSet;
protected:
	SocketSet* service_ptr_ = nullptr;
public:
	//
	inline SocketSet* this_service() { return service_ptr_; }

protected:
	//
	virtual void OnAttachService(Service* pSvr)
	{
		Base::OnAttachService(pSvr);
		service_ptr_ = dynamic_cast<SocketSet*>(pSvr);
	}
	virtual void OnDeatchService(Service* pSvr)
	{
		service_ptr_ = nullptr;
	}
};

/*!
 *	@brief SimpleEvtSocketT 定义.
 *
 *	封装SimpleEvtSocketT，增加事件服务接口，实现简单的流式发送/接收（写入/读取）网络架构
 */
template<class TBase>
class SimpleEvtSocketT : public SimpleSvrSocketT<TBase>
{
	typedef SimpleSvrSocketT<TBase> Base;
public:
	typedef typename Base::SocketSet EvtSocketSet;
	typedef typename EvtSocketSet::Event Event;
public:

	inline void Post(const Event& evt) {
		// if(!evt.dst) {
		// 	evt.dst = this;
		// }
		Base::this_service()->Post(evt);
	}
	
	virtual void OnEvent(const Event& evt)
	{
	}
};

/*!
 *	@brief SimpleTaskSocketT 定义.
 *
 *	封装SimpleTaskSocketT，增加任务调用支持，支持异步DNS
 */
template<class TBase>
class SimpleTaskSocketT : public SimpleSvrSocketT<TBase>
{
	typedef SimpleTaskSocketT<TBase> Base;
public:
	typedef typename Base::SocketSet TaskSocketSet;
public:
	
	inline /*std::future<struct addrinfo*>*/void Resolve(const char *hostname, const char *service, const struct addrinfo *hints)
	{
		auto result = std::async(//std::launch::async|std::launch::deferred,
		//return ThreadPool::Inst().Post(
			[this,hostname,service,hints] {
			struct addrinfo* res = nullptr;
			GetAddrInfo(hostname,service,hints,&res);
			this_service()->Post(std::bind(this, &OnResolve, res));
			return res;
		});
	#if 0
		std::future_status status;
		do {
			status = result.wait_for(std::chrono::milliseconds(10));
			switch (status)
			{
			case std::future_status::ready:
				PRINTF("AsyncGetAddrInfo Ready...");
				break;
			case std::future_status::timeout:
				PRINTF("AsyncGetAddrInfo Wait...");
				break;
			case std::future_status::deferred:
				PRINTF("AsyncGetAddrInfo Deferred...");
				break;
			default:
				break;
			}

		} while (status != std::future_status::ready);
		struct addrinfo *ai_result = result.get();
	#endif//
		//return result;
	}

protected:
	//
	virtual void OnResolve(struct addrinfo *res)
	{

	}
};

/*!
 *	@brief SimpleTaskService 定义.
 *
 *	封装SimpleTaskService，实现简单事件服务
 */
template<class TBase/* = Service*/>
class SimpleTaskServiceT : public TBase
{
	typedef TBase Base;
protected:
	struct Event : public DealyEventBase
	{
		typedef DealyEventBase Base;
		Event(std::function<void()> &&_task, void* _ptr = nullptr, size_t _delay = 0, size_t _repeat = 0)
		:Base(_delay, _repeat), ptr(_ptr), task(std::move(_task)) {
			//PRINTF("Event");
		}
		Event(const Event& o):Base(o), ptr(o.ptr), task(o.task) {
			//PRINTF("levent");
		}
		Event(Event&& o):Base(o), ptr(o.ptr), task(std::move(o.task)) {
			//PRINTF("revent");
		}
		~Event() {
		}

		Event& operator = (const Event& rhs) {
			if(this == &rhs) return *this;
			DealyEventBase::operator=(rhs);
			ptr = rhs.ptr;
			task = rhs.task;
        	return *this;
    	}
		Event& operator = (Event&& rhs) {
			if(this == &rhs) return *this;
			DealyEventBase::operator=(std::move(rhs));
			ptr = rhs.ptr;
			task = std::move(rhs.task);
        	return *this;
    	}

		void* ptr = nullptr;
		std::function<void()> task;
	};
	std::vector<Event> queue_;
	std::mutex mutex_;
	//
	/*template<class... _Valty>	
	inline void InnerPost(_Valty&&... _Val) {
		std::lock_guard<std::mutex> lock(mutex_);
		queue_.emplace_back(std::forward<_Valty>(_Val)...);
		Base::PostNotify();
	}*/
public:
	SimpleTaskServiceT()
	{
		queue_.reserve(1024);
	}

	inline void Post(std::function<void()> && task, void* ptr = nullptr, size_t delay = 0, size_t repeat = 0)
	{
		ASSERT(task);
		Event evt(std::move(task), ptr, delay, repeat);
		{
		std::lock_guard<std::mutex> lock(mutex_);
		//实时任务排在延迟任务前面，延迟任务按延迟时间和重复次数排队，延迟短和重复次数少排在前面,消费任务从头开始消费
		auto it = std::upper_bound(queue_.begin(), queue_.end(), evt);
		queue_.emplace(it,std::move(evt));
		//queue_.emplace(it.base(),std::forward<std::function<void()>>(task), ptr, delay, repeat);
		}
		if(delay) {
			Base::PostTimer(delay);
		} else {
			Base::PostNotify();	
		}
	}

	template<class F, class... Args>
	static inline std::function<void()> Package(std::future<typename std::result_of<F(Args...)>::type>& fu, F&& f, Args&&... args)
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);

		fu = task->get_future();

		return [task](){ (*task)(); };
	}

protected:
	//
	inline void RemoveSocket(SocketEx* sock_ptr) {
		std::unique_lock<std::mutex> lock(mutex_);
		for(int i = queue_.size() - 1; i >= 0; i--)
		{
			const Event& evt = queue_[i];
			if (evt.ptr == sock_ptr) {
				queue_.erase(queue_.begin() + i);
			}
		}
	}

	void DoTask(bool timer = false)
	{
		//从头开始消费
		std::unique_lock<std::mutex> lock(mutex_);
		size_t i = 0, j = queue_.size(), k = 0;
		if(timer) {
			for(; i < j; i++)
			{
				const Event& evt = queue_[i];
				if(evt.IsDelay()) {
					break;
				}
			}
		}
		for(k = i; i < j; i++)
		{
			Event evt = queue_[k];
			lock.unlock();
			uint32_t millis = 0;
			if (evt.IsActive(&millis)) {
				evt.task();
				if (evt.IsRepeat()) {
					evt.Update();
					k++;
				} else {
					queue_.erase(queue_.begin()+k);
				}
			} else {
				if(timer) {
					Base::PostTimer(millis);
				}
				break;
			}
			lock.lock();
			if (queue_.empty()) {
				break;
			}
		}
	}
	
	virtual void OnIdle()
	{
		DoTask();
	}
	
	virtual void OnNotify()
	{
		DoTask();
	}
	
	virtual void OnTimer()
	{
		DoTask(true);
	}
};

/*!
 *	@brief SimpleEvtService 定义.
 *
 *	封装SimpleEvtService，实现简单事件服务
 */
template<class TBase/* = EventService*/>
class SimpleEvtServiceT : public TBase
{
	typedef TBase Base;
public:
	typedef typename TBase::Event Event;
protected:
	//Queue<Event> queue_;
	std::vector<Event> queue_;
	std::mutex mutex_;
	//std::condition_variable cv_;
public:
	SimpleEvtServiceT()
	{
		queue_.reserve(1024);
	}

	inline void Post(const Event& evt) {
		std::lock_guard<std::mutex> lock(mutex_);
		queue_.emplace_back(evt);
		Base::PostNotify();
	}

protected:
	//
	inline void RemoveSocket(SocketEx* sock_ptr) {
		std::unique_lock<std::mutex> lock(mutex_);
		for(int i = queue_.size() - 1; i >= 0; i--)
		{
			const Event& evt = queue_[i];
			if(auto tsock_ptr = Base::IsSocketEvent(evt)) {
				if (tsock_ptr == sock_ptr) {
					queue_.erase(queue_.begin() + i);
				}
			}
		}
	}

	inline bool Pop(Event& evt) {
		std::unique_lock<std::mutex> lock(mutex_);
		if (!queue_.empty()) {
			evt = queue_[0];
			queue_.erase(queue_.begin());
			return true;
		}
		return false;
	}

	virtual void OnNotify()
	{
		for(size_t i = 0, j = queue_.size(); i < j; i++)
		{
			Event evt;
			if (Pop(evt)) {
				if (Base::IsActive(evt)) {
					OnEvent(evt);
					if (Base::IsRepeat(evt)) {
						Base::UpdateRepeat(evt);
						Post(evt);
					}
				} else {
					Post(evt);
				}
			}
		}
	}

	virtual void OnEvent(Event& evt)
	{
		
	}
};

/*!
 *	@brief SimpleSocketEvtService 定义.
 *
 *	封装SimpleSocketEvtService，实现Socket事件服务
 */
template<class TBase/* = EventService*/>
class SimpleSocketEvtServiceT : public SimpleEvtServiceT<TBase>
{
	typedef SimpleEvtServiceT<TBase> Base;
public:
	typedef typename Base::Event Event;

protected:
	//
	virtual void OnEvent(Event& evt)
	{
		if(auto sock_ptr = Base::IsSocketEvent(evt)) {
			sock_ptr->OnEvent(evt);
		}
	}
};

}

#endif//_H_XSOCKETIMPL_H_
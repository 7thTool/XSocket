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
	//MSG_DONTROUTE,
	//MSG_PARTIAL,
	//...
	//
	SOCKET_PACKET_FLAG_NONE			= 0,			//未知
	SOCKET_PACKET_FLAG_PENDING		= 0X00010000,	//未完成
	SOCKET_PACKET_FLAG_COMPLETE		= 0X00020000,	//是完整的包
	SOCKET_PACKET_FLAG_SEND			= 0X00040000,	//是发送包
	SOCKET_PACKET_FLAG_RECEIVE		= 0X00080000,	//是接收包
	SOCKET_PACKET_FLAG_PUSH			= 0X00100000,	//是推送包
	SOCKET_PACKET_FLAG_RESPONSE		= 0X00200000,	//是发送包的回应包
	SOCKET_PACKET_FLAG_CONTINUE		= 0X00400000,	//是还要继续收包
	SOCKET_PACKET_FLAG_HEARTBEAT	= 0X00800000,	//是心跳包
	SOCKET_PACKET_FLAG_TEMPBUF		= 0X80000000,	//临时内存，不能引用buf指针
};

/*!
 *	@brief SocketWrapper 定义.
 *
 *	封装SocketEx，定义对称的发送/接收（写入/读取）网络架构
 */
template<class TBase = SocketEx>
class SocketWrapper : public TBase
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
	SocketWrapper()
		:Base()
		,m_nRecvLen(0)
		,m_pRecvBuf(NULL)
		,m_nRecvBufLen(0)
		,m_nSendLen(0)
		,m_pSendBuf(NULL)
		,m_nSendBufLen(0)
	{
		
	}

	virtual ~SocketWrapper()
	{

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
	//接收完整一个包后的处理
	virtual void OnRecvBufAfter(char* & lpBuf, int & nBufLen)
	{
		if(m_pRecvBuf) {
			if(nBufLen < m_nRecvLen) {
				//需要移动数据
				m_nRecvLen = m_nRecvLen-nBufLen;
				memmove(m_pRecvBuf, m_pRecvBuf + nBufLen, m_nRecvLen);
			} else {
				m_nRecvLen = 0;
				//m_pRecvBuf;
				//m_nRecvBufLen;
			}
		}
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
			char* lpBuf = NULL;
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
			if (nBufLen<=0) {
				nErrorCode = GetLastError();
				switch(nErrorCode)
				{
				case 0:
					break;
#ifdef WIN32
				case WSAEWOULDBLOCK:
				case WSA_IO_PENDING:
					break;
#else
				case EWOULDBLOCK:
					break;
				case EINTR:
					bConitnue = true;
					break;
#endif//
				default:
					OnClose(nErrorCode);
					break;
				}
			} else {
				OnReceive(lpBuf, nBufLen, 0);
				bConitnue = IsSocket();
			}
		} while (bConitnue);
	}

	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags) 
	{
		m_nRecvLen += nBufLen;
		int nParseBufLen = m_nRecvLen;
		int nParseFlags = ParseBuf(m_pRecvBuf, nParseBufLen);
		if (SOCKET_PACKET_FLAG_COMPLETE & nParseFlags) {
			OnRecvBuf(m_pRecvBuf, nParseBufLen, nParseFlags);
			OnRecvBufAfter(m_pRecvBuf, nParseBufLen);
		} else {
			PrepareExpandRecvBuf(m_pRecvBuf, m_nRecvBufLen);
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
			const char* lpBuf = NULL;
			int nBufLen = 0;
			if (!m_pSendBuf) {
				if(!PrepareSendBuf(lpBuf,nBufLen)) {
					//说明没有可发送数据
					RemoveSelect(FD_WRITE);
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
			if (nBufLen<=0) {
				nErrorCode = GetLastError();
				switch(nErrorCode)
				{
				case 0:
					break;
#ifdef WIN32
				case WSAEWOULDBLOCK:
				case WSA_IO_PENDING:
					break;
#else
				case EWOULDBLOCK:
					break;
				case EINTR:
					break;
#endif//
				default:
					OnClose(nErrorCode);
					break;
				}
			} else {
				OnSend(lpBuf, nBufLen, 0);
				bConitnue = IsSocket(); //继续发送
			}
		} while (bConitnue);
	}

	virtual void OnSend(const char* lpBuf, int nBufLen, int nFlags)
	{
		m_nSendLen += nBufLen;
		if (m_nSendLen >= m_nSendBufLen) {
			OnSendBuf(m_pSendBuf, m_nSendLen);
			m_nSendLen = 0;
			m_pSendBuf = NULL;
			m_nSendBufLen = 0;
		}
	}

	void OnClose(int nErrorCode)
	{
		Base::OnClose(nErrorCode);
		m_nRecvLen = 0;
		m_pRecvBuf = NULL;
		m_nRecvBufLen = 0;
		m_nSendLen = 0;
		m_pSendBuf = NULL;
		m_nSendBufLen = 0;
	}
};

/*!
 *	@brief SampleSocketImpl 定义.
 *
 *	封装SampleSocketImpl，实现简单的流式发送/接收（写入/读取）网络架构
 */
template<class TBase, u_short uMaxBufSize = 8*1024>
class SampleSocketImpl : public TBase
{
	typedef TBase Base;
protected:
	typedef std::string SampleBuffer;
	SampleBuffer m_RecvBuffer;
	SampleBuffer m_SendBuffer;
	SampleBuffer m_PrepareSendBuffer;
	//std::mutex m_SendSection;
	//std::mutex m_RecvSection;

public:
	SampleSocketImpl()
	{
		m_RecvBuffer.reserve(uMaxBufSize);
		m_RecvBuffer.resize(uMaxBufSize);
		m_SendBuffer.reserve(uMaxBufSize);
		m_PrepareSendBuffer.reserve(uMaxBufSize);
	}

	virtual ~SampleSocketImpl()
	{
		
	}

	int SendBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);

		m_SendBuffer.insert(m_SendBuffer.end(),lpBuf,lpBuf+nBufLen);

		if(!IsSelect(FD_WRITE)) {
			Select(FD_WRITE);
		}

		return nBufLen;
	}

// 	int RecvBuf(char* lpBuf, int nBufLen, int* nFlags = NULL)
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
// 			int nBufLen = Receive(NULL,0,&nFlags);
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
	//SocketWrapper 实现接口
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

protected:
	//
	virtual void OnClose(int nErrorCode)
	{
		Base::OnClose(nErrorCode);
		
		//std::unique_lock<std::mutex> lock(m_SendSection);

		m_PrepareSendBuffer.clear();
		m_SendBuffer.clear();
		//lock.unlock();
	}
};

/*!
 *	@brief SocketArchitectureImpl 定义.
 *
 *	封装SocketArchitectureImpl，实现块状的数据包式的发送/接收（写入/读取）网络架构
 */
template<class TBase, u_short uMaxBufSize = 1024>
class SocketArchitectureImpl : public TBase
{
	typedef TBase Base;
protected:
	typedef struct tagSABuf
	{
		int nSendBufLen;
		const char* pSendBuf;
		int nSendFlags;
		int nRecvLen;
		char RecvBuf[uMaxBufSize];
		int nRecvFlags;
	}SABUF,*PSABUF;
	typedef std::queue<SABUF> PACKList;
	PACKList m_RecvPackList;
	PACKList m_SendPackList;
	std::mutex m_SendSection;
	std::mutex m_RecvSection;

public:
	SocketArchitectureImpl()
	{
		
	}

	virtual ~SocketArchitectureImpl()
	{
		
	}

	int Send(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		std::unique_lock<std::mutex> lock(m_SendSection);

		SABUF saZero = {0};
		m_SendPackList.push(saZero);
		SABUF & saBuf = m_SendPackList.back();
		if (nFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
			char* pTempBuf = new char[nBufLen+1];
			memcpy(pTempBuf,lpBuf,nBufLen);
			pTempBuf[nBufLen] = 0;
			saBuf.pSendBuf = pTempBuf;
		} else {
			saBuf.pSendBuf = lpBuf;
		}
		saBuf.nSendBufLen = nBufLen;
		saBuf.nSendFlags = nFlags;
		return nBufLen;
	}

	int Receive(char* lpBuf, int nBufLen = uMaxBufSize, int* nFlags = NULL)
	{
		std::unique_lock<std::mutex> lock(m_RecvSection);

		if (!m_RecvPackList.empty()) {
			SABUF & saBuf = m_RecvPackList.front();
			if (nFlags) {
				*nFlags = saBuf.nRecvFlags;
			}
			if (saBuf.nRecvFlags&SOCKET_PACKET_FLAG_COMPLETE) {
				if (nBufLen>=saBuf.nRecvLen) {
					memcpy(lpBuf,saBuf.RecvBuf,saBuf.nRecvLen);
					m_RecvPackList.pop();
				}
				return saBuf.nRecvLen;
			}
		}
		return 0;
	}

	void Dispatch()
	{
		char lpBuf[uMaxBufSize];
		int nBufLen = uMaxBufSize;
		int nFlags = 0;
		while ((nBufLen=Receive(lpBuf,nBufLen,&nFlags))>0)
		{
			if (nFlags&SOCKET_PACKET_FLAG_RESPONSE) {
				OnResponse(lpBuf,nBufLen,nFlags);
			} else {
				OnPush(lpBuf,nBufLen,nFlags);
			}
		}
	}

protected:
	//Dispatch 实现接口 
	virtual void OnResponse(const char* lpBuf, int nBufLen, int nFlags)
	{

	}

	virtual void OnPush(const char* lpBuf, int nBufLen, int nFlags)
	{

	}

protected:
	//SocketWrapper 实现接口
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen)
	{
		SABUF saZero = {0};
		m_RecvPackList.push(saZero);
		SABUF & saBuf = m_RecvPackList.back();
		lpBuf = saBuf.RecvBuf;
		nBufLen = uMaxBufSize;
		return true;
	}

	virtual void OnReceive(const char* lpBuf, int nBufLen, int nFlags) 
	{
		Base::OnReceive(lpBuf, nBufLen, nFlags);

		std::unique_lock<std::mutex> lock(m_RecvSection);

		ASSERT (lpBuf && nBufLen);
		SABUF & saBuf = m_RecvPackList.back();
		ASSERT(saBuf.RecvBuf==lpBuf);
		saBuf.nRecvLen = nBufLen;
		saBuf.nRecvFlags = nFlags;
	}

	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
	{
		std::unique_lock<std::mutex> lock(m_SendSection);

		if (!m_SendPackList.empty()) {
			SABUF & saBuf = m_SendPackList.front();
			lpBuf = saBuf.pSendBuf;
			nBufLen = saBuf.nSendBufLen;
			return true;
		}
		return false;
	}

	virtual void OnSend(const char* lpBuf, int nBufLen) 
	{
		Base::OnSend(lpBuf, nBufLen);

		std::unique_lock<std::mutex> lock(m_SendSection);

		ASSERT (lpBuf && nBufLen);
		SABUF & saBuf = m_SendPackList.front();
		ASSERT(saBuf.pSendBuf==lpBuf && saBuf.nSendBufLen==nBufLen);
		if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
			delete []saBuf.pSendBuf;
		}
		m_SendPackList.pop();
	}

	void OnClose(int nErrorCode)
	{
		Base::OnClose(nErrorCode);
		
		std::unique_lock<std::mutex> LockSend(m_SendSection);
		while (!m_SendPackList.empty())
		{
			SABUF & saBuf = m_SendPackList.front();
			if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
				delete []saBuf.pSendBuf;
			}
			m_SendPackList.pop();
		}
		LockSend.unlock();

		std::unique_lock<std::mutex> LockRecv(m_RecvSection);
		while (!m_RecvPackList.empty())
		{
			SABUF & saBuf = m_RecvPackList.front();
			if (saBuf.nSendFlags&SOCKET_PACKET_FLAG_TEMPBUF) {
				delete []saBuf.pSendBuf;
			}
			m_RecvPackList.pop();
		}
		LockRecv.unlock();
	}
};

//////////////////////////////////////////////////////////////////////////

/*!
 *	@brief SampleUdpSocketArchitecture 定义.
 *
 *	封装SampleUdpSocketArchitecture，定义简单的Udp数据包网络架构
 */
template<class TBase = SocketEx, class SockAddrType = SOCKADDR_IN>
class SampleUdpSocketArchitecture : public TBase
{
	typedef TBase Base;
protected:
	int m_nSendLen;
	const char* m_pSendBuf;
	int m_nSendBufLen;
	const SockAddrType* m_pSendAddr;
public:
	SampleUdpSocketArchitecture()
		:Base()
		,m_nSendLen(0)
		,m_pSendBuf(NULL)
		,m_nSendBufLen(0)
		,m_pSendAddr(NULL)
	{

	}

	virtual ~SampleUdpSocketArchitecture()
	{

	}

	int Close()
	{
		int rlt = Base::Close();
		m_nSendLen = 0;
		m_pSendBuf = NULL;
		m_nSendBufLen = 0;
		m_pSendAddr = NULL;
		return rlt;
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen, const SockAddrType & SockAddr) { return SOCKET_PACKET_FLAG_COMPLETE; }

	//准备接收缓存
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen, SockAddrType* & lpSockAddr)
	{
		return false;
	}

	//接收完整一个包
	virtual void OnReceive(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr)
	{

	}

	//准备发送数据包
	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen, const SockAddrType* & lpSockAddr)
	{
		return false;
	}

	//发送完整一个包
	virtual void OnSend(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr)
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
			SockAddrType SockAddr;
			int nSockAddrLen = sizeof(SockAddrType);
			nBufLen = Base::ReceiveFrom(lpBuf,nBufLen,(SOCKADDR*)&SockAddr,&nSockAddrLen);
			if (nBufLen<=0) {
				nErrorCode = GetLastError();
				switch(nErrorCode)
				{
				case EWOULDBLOCK:
					break;
#ifdef WIN32
				case WSA_IO_PENDING:
					break;
#else
				case EINTR:
					bConitnue = true;
					break;
#endif//
				default:
					OnClose(nErrorCode);
					break;
				}
			} else {
				ASSERT(nSockAddrLen==sizeof(SockAddrType));
	#if 0
				PRINTF("(%s:%d):%s\n",N2Ip(SockAddr.sin_addr.s_addr),N2H(SockAddr.sin_port),lpBuf);
	#endif//
				//int nFlags = ParseBuf(lpBuf,nBufLen,SockAddr);
				OnReceive(lpBuf,nBufLen,SockAddr);
				//bConitnue = true;
			}
		} while(bConitnue);
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
			const char* lpBuf = NULL;
			int nBufLen = 0;
			const SockAddrType* lpSockAddr;
			if (!m_pSendBuf) {
				if(!PrepareSendBuf(lpBuf,nBufLen,lpSockAddr)) {
					//说明没有可发送数据
					return;
				}
				m_nSendLen = 0;
				m_pSendBuf = lpBuf;
				m_nSendBufLen = nBufLen;
				m_pSendAddr = lpSockAddr;
			}
			lpBuf = m_pSendBuf+m_nSendLen;
			nBufLen = (int)(m_nSendBufLen-m_nSendLen);
			lpSockAddr = m_pSendAddr;
			ASSERT(lpBuf && nBufLen>0);
	#if 0
			PRINTF("echo:(%s:%d)\n",N2Ip(lpSockAddr->sin_addr.s_addr),N2H(lpSockAddr->sin_port));
	#endif//
			nBufLen = Base::SendTo(lpBuf,nBufLen,(const SOCKADDR*)lpSockAddr,sizeof(SockAddrType));
			if (nBufLen<=0) {
				nErrorCode = GetLastError();
				switch(nErrorCode)
				{
				case EWOULDBLOCK:
					break;
#ifdef WIN32
				case WSA_IO_PENDING:
					break;
#else
				case EINTR:
					break;
#endif//
				default:
					OnClose(nErrorCode);
					break;
				}
			} else {
				m_nSendLen += nBufLen;
				lpBuf = m_pSendBuf;
				nBufLen = m_nSendLen;
				lpSockAddr = m_pSendAddr;
				if(nBufLen>=m_nSendBufLen) {
					OnSend(lpBuf,nBufLen,*lpSockAddr);
					m_nSendLen = 0;
					m_pSendBuf = NULL;
					m_nSendBufLen = 0;
					m_pSendAddr = NULL;
					//bConitnue = true; //继续发送
				} else {
					ASSERT(0); //UDP 不应该发送太大的包导致发不完，建议520字节包
				}
			}
		} while(bConitnue);
	}
};

/*!
 *	@brief SampleUdpSocketArchitectureImpl 定义.
 *
 *	封装SampleUdpSocketArchitectureImpl，实现简单的Udp数据包网络架构
 */
template<class TBase, class SockAddrType = SOCKADDR_IN>
class SampleUdpSocketArchitectureImpl : public TBase
{
	typedef TBase Base;
protected:
	typedef std::string SampleBuffer;
	SampleBuffer m_RecvBuffer;
	SampleBuffer m_SendBuffer;
	SampleBuffer m_PrepareSendBuffer;
	std::mutex m_SendSection;
	std::mutex m_RecvSection;

public:
	SampleUdpSocketArchitectureImpl()
	{
		m_RecvBuffer.reserve(8*1024); //8k
		m_SendBuffer.reserve(8*1024); //8k
		m_PrepareSendBuffer.reserve(1024); //1k
	}

	virtual ~SampleUdpSocketArchitectureImpl()
	{
		
	}

	int Close()
	{
		int rlt = Base::Close();

		std::unique_lock<std::mutex> LockSend(m_SendSection);

		m_PrepareSendBuffer.clear();
		m_SendBuffer.clear();
		LockSend.unlock();

		std::lock_guard<std::mutex> LockRecv(m_RecvSection);

		m_RecvBuffer.clear();
		LockRecv.unlock();

		return rlt;
	}

	int Send(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr, int nFlags = 0)
	{
		std::unique_lock<std::mutex> lock(m_SendSection);

		const char* pPack = NULL;
		int nPackLen = sizeof(int) + sizeof(SockAddrType) + nBufLen;
		pPack = (const char*)&nPackLen;
		m_SendBuffer.insert(m_SendBuffer.end(),pPack,pPack+sizeof(int));
		pPack = (const char*)&SockAddr;
		m_SendBuffer.insert(m_SendBuffer.end(),pPack,pPack+sizeof(SockAddrType));
		m_SendBuffer.insert(m_SendBuffer.end(),lpBuf,lpBuf+nBufLen);

		return nBufLen;
	}

	int Receive(char* lpBuf, int nBufLen, SockAddrType* lpSockAddr, int* nFlags = NULL)
	{
		std::unique_lock<std::mutex> lock(m_RecvSection);
		ASSERT(nFlags);
		int nRecvBufLen = m_RecvBuffer.size();
		if (nRecvBufLen>0) {
			ASSERT(nRecvBufLen>(sizeof(int)+sizeof(SockAddrType)));
			int* pPackLen = (int*)&m_RecvBuffer[0];
			SockAddrType* pPackAddr = (SockAddrType*)(pPackLen+1);
			const char* pPackBuf = (const char*)(pPackAddr+1);
			ASSERT(*pPackLen<=nRecvBufLen);
			int nPackBufLen = (*pPackLen-(sizeof(int)+sizeof(SockAddrType)));
			if (lpSockAddr) {
				*lpSockAddr = *pPackAddr;
			}
			if (nBufLen>=nPackBufLen) {
				nBufLen = nPackBufLen;
				memcpy(lpBuf,pPackBuf,nBufLen);
				m_RecvBuffer.erase(m_RecvBuffer.begin(),m_RecvBuffer.begin()+*pPackLen);
			}
			return nPackBufLen;
		}
		return 0;
	}

	/*void Dispatch()
	{
		int nFlags = 0;
		do
		{
			int nBufLen = Receive(NULL,0);
			if (!(nFlags&SOCKET_PACKET_FLAG_COMPLETE)) {
				break;
			}
			string Buf(nBufLen,0);
			char* lpBuf = (char*)Buf.c_str();
			nBufLen = Receive(lpBuf,nBufLen);
			if (nFlags&SOCKET_PACKET_FLAG_RESPONSE) {
				OnResponse(lpBuf,nBufLen,nFlags);
			} else {
				OnPush(lpBuf,nBufLen,nFlags);
			}
		} while(true);
	}

protected:
	//Dispatch 实现接口 
	virtual void OnResponse(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr, int nFlags)
	{

	}

	virtual void OnPush(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr, int nFlags)
	{

	}*/

protected:
	//SocketWrapper 实现接口
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen, SockAddrType* & lpSockAddr)
	{
		return false;
	}

	virtual void OnReceive(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr) 
	{
		Base::OnReceive(lpBuf, nBufLen, SockAddr);

		std::unique_lock<std::mutex> lock(m_RecvSection);

		const char* pTempBuf = NULL;
		int nPackLen = sizeof(int) + sizeof(SockAddrType) + nBufLen;
		pTempBuf = (const char*)&nPackLen;
		m_RecvBuffer.insert(m_RecvBuffer.end(),pTempBuf,pTempBuf+sizeof(int));
		pTempBuf = (const char*)&SockAddr;
		m_RecvBuffer.insert(m_RecvBuffer.end(),pTempBuf,pTempBuf+sizeof(SockAddrType));
		m_RecvBuffer.insert(m_RecvBuffer.end(),lpBuf,lpBuf+nBufLen);
	}

	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen, const SockAddrType* & lpSockAddr)
	{
		std::unique_lock<std::mutex> lock(m_SendSection);

		int nSendBufLen = m_SendBuffer.size();
		if (nSendBufLen>0) {
			ASSERT(nSendBufLen>sizeof(int)+sizeof(SockAddrType));
			int nPackLen = 0;
			int nOffset = 0;
			do
			{
				nPackLen = *(int*)&m_SendBuffer[nOffset];
				nOffset += nPackLen;
			} while(nOffset<nSendBufLen);
			ASSERT(nOffset==nSendBufLen);
			m_PrepareSendBuffer.assign(m_SendBuffer.end()-nPackLen,m_SendBuffer.end());
			m_SendBuffer.erase(m_SendBuffer.end()-nPackLen,m_SendBuffer.end());
			int* pPackLen = (int*)&m_PrepareSendBuffer[0];
			const SockAddrType* pPackAddr = (const SockAddrType*)(pPackLen+1);
			const char* pPackBuf = (const char*)(pPackAddr+1);
			lpBuf = pPackBuf;
			nBufLen = *pPackLen-(sizeof(int)+sizeof(SockAddrType));
			lpSockAddr = pPackAddr;
			lock.unlock();
			return true;
		}

		return false;
	}

	virtual void OnSend(const char* lpBuf, int nBufLen, const SockAddrType & SockAddr) 
	{
		Base::OnSend(lpBuf, nBufLen, SockAddr);
	}
};


/*!
 *	@brief StableUdpSocketArchitectureImpl 定义.
 *
 *	封装StableUdpSocketArchitectureImpl，定义基于UDP的稳定可靠传输的网络架构
 *  
 *  实现类似于TCP协议的超时重传，有序接受，应答确认，滑动窗口流量控制等机制，
 *	使用UDP数据包+序列号，UDP数据包+时间戳，应答确认机制。
 *	|8字节首部|最大512长度内容|=520字节。
 */
//template<class TBase, class SockAddrType = SOCKADDR_IN>
//class StableUdpSocketArchitectureImpl : public SampleUdpSocketArchitectureImpl<TBase,SockAddrType>
//{
//	typedef SampleUdpSocketArchitectureImpl<TBase,SockAddrType> Base;
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
//	StableUdpSocketArchitectureImpl()
//		:Base()
//	{
//
//	}
//
//	virtual ~StableUdpSocketArchitectureImpl()
//	{
//
//	}
//
//	int Close()
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

}

#endif//_H_XSOCKETIMPL_H_
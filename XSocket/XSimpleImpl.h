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
#ifndef _H_XSIMPLEIMPL_H_
#define _H_XSIMPLEIMPL_H_

#include "XSocketImpl.h"

#include <string>
#include <queue>
#include <list>
#include <map>
using namespace std;

namespace XSocket {

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

/*!
 *	@brief 简单的SimpleConnectionT封装.
 *
 *	SimpleConnectionT定义了应用层连接接口和基本实现
 */
template<class TSocket>
class SimpleConnectionT : public ConnectionT<TSocket>
{
	typedef ConnectionT<TSocket> Base;
public:

	inline std::string& SendBuf() 
	{
		return Base::sock_->SendBuf();
	}

	inline int SendBuf(const std::string& Buf, int nFlags = 0)
	{
		return Base::sock_->SendBuf(Buf, nFlags);
	}

	inline int SendBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		return Base::sock_->SendBuf(lpBuf, nBufLen, nFlags);
	}

};

//////////////////////////////////////////////////////////////////////////

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
 *	@brief 简单的SimpleUdpConnectionT封装.
 *
 *	SimpleUdpConnectionT定义了应用层连接接口和基本实现
 */
template<class TSocket>
class SimpleUdpConnectionT : public ConnectionT<TSocket>
{
	typedef ConnectionT<TSocket> Base;
public:
	typedef typename TSocket::SockAddr SockAddr;
protected:
	SockAddr addr_;
public:
	SimpleUdpConnectionT(TSocket* sock, const SockAddr& addr):Base(this),addr_(addr){}

	int SendBuf(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
		return Base::sock_->SendBuf(lpBuf, nBufLen, addr_, nFlags);
	}
};

}

#endif//_H_XSIMPLEIMPL_H_
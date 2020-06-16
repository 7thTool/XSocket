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
 *	@brief CustomSocketT 定义.
 *
 *	封装CustomSocketT，实现自定义的快速发送/接收（写入/读取）网络架构
 */
template<class TBase, class TSendBuffer>
class CustomSocketT : public TcpSocket<TBase>
{
	typedef TcpSocket<TBase> Base;
public:
	typedef std::string RecvBuffer;
	typedef TSendBuffer SendBuffer;
protected:
	RecvBuffer recv_buf_;
	std::vector<SendBuffer> send_que_;
	//std::mutex m_SendSection;
public:
	CustomSocketT()
	{
		
	}

	virtual ~CustomSocketT()
	{
		
	}

	inline void ReserveRecvBufSize(size_t size) {
		recv_buf_.reserve(size);
		recv_buf_.resize(size);
	}

	inline void ReserveSendQueSize(size_t size) {
		send_que_.reserve(size);
	}

	inline int Close()
	{
		int ret = Base::Close();
		//std::unique_lock<std::mutex> lock(m_SendSection);

		send_que_.clear();
		//lock.unlock();
		return ret;
	}

	inline size_t NotSendBufSize() 
	{
		size_t size = 0;
		for(auto& send_buf : send_que_)
		{
			size += send_buf.size();
		}
		return size;
	}

	inline SendBuffer& SendBuf() 
	{
		send_que_.emplace_back();
		return send_que_.back();
	}

	inline void SendBuf(const SendBuffer& buf)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);
		ASSERT(buf.data() && buf.size()>0);
		send_que_.emplace_back(buf);
		SendBufDirect();
	}

	inline void SendBuf(const char* lpBuf, int nBufLen)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);
		SendBuf().set_data(lpBuf,nBufLen);
		return SendBufDirect();
	}

	inline void SendBufDirect()
	{
		ASSERT(Base::IsSocket());
		if(!Base::IsSelect(FD_WRITE)) {
			Base::Select(FD_WRITE);
		}
	}
protected:
	//TcpSocket 实现接口
	virtual bool PrepareRecvBuf(char* & lpBuf, int & nBufLen)
	{
		lpBuf = &recv_buf_[0];
		nBufLen = recv_buf_.size();

		return true;
	}
	virtual bool PrepareExpandRecvBuf(char* & lpBuf, int & nBufLen)
	{
		recv_buf_.resize(recv_buf_.size() + recv_buf_.size()/2);
		lpBuf = &recv_buf_[0];
		nBufLen = recv_buf_.size();
		return true;
	}

	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
	{
		//std::unique_lock<std::mutex> lock(m_SendSection);
		if(!send_que_.empty()) {
			SendBuffer& send_buf = send_que_[0];
			lpBuf = send_buf.data();
			nBufLen = send_buf.size();
			ASSERT(lpBuf && nBufLen>0);
			//lock.unlock();
			return true;
		}
		return false;
	}

	virtual void OnSendBuf(const char* lpBuf, int nBufLen) 
	{
		Base::OnSendBuf(lpBuf, nBufLen);

		//std::unique_lock<std::mutex> lock(m_SendSection);
		ASSERT(!send_que_.empty());
		send_que_.erase(send_que_.begin());
	}
};

/*!
 *	@brief SimpleSocketT 定义.
 *
 *	封装SimpleSocketT，实现简单的流式发送/接收（写入/读取）网络架构
 */
template<class TBase>
class SimpleSocketT : public TcpSocket<TBase>
{
	typedef TcpSocket<TBase> Base;
public:
	typedef std::string RecvBuffer;
	typedef std::string SendBuffer;
protected:
	RecvBuffer recv_buf_;
	SendBuffer send_buf_;
	SendBuffer ppr_send_buf_;
	//std::mutex m_SendSection;
	//std::mutex m_RecvSection;

public:
	SimpleSocketT()
	{
		// recv_buf_.reserve(uMaxBufSize);
		// recv_buf_.resize(uMaxBufSize);
		// send_buf_.reserve(uMaxBufSize);
		// ppr_send_buf_.reserve(uMaxBufSize);
	}

	virtual ~SimpleSocketT()
	{
		
	}

	inline void ReserveRecvBufSize(size_t size) {
		recv_buf_.reserve(size);
		recv_buf_.resize(size);
	}

	inline void ReserveSendBufSize(size_t size) {
		send_buf_.reserve(size);
		ppr_send_buf_.reserve(size);
	}

	inline int Close()
	{
		int ret = Base::Close();
		//std::unique_lock<std::mutex> lock(m_SendSection);

		ppr_send_buf_.clear();
		send_buf_.clear();
		//lock.unlock();
		return ret;
	}

	inline size_t NotSendBufSize() 
	{
		return send_buf_.size() + ppr_send_buf_.size();
	}

	inline SendBuffer& SendBuf() 
	{
		return send_buf_;
	}

	inline void SendBuf(const SendBuffer& Buf)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);
		
		send_buf_ += Buf;

		SendBufDirect();
	}

	inline void SendBuf(const char* lpBuf, int nBufLen)
	{
		//std::lock_guard<std::mutex> lock(m_SendSection);

		send_buf_.append(lpBuf,lpBuf+nBufLen);

		return SendBufDirect();
	}

	inline void SendBufDirect()
	{
		ASSERT(Base::IsSocket());
		if(!Base::IsSelect(FD_WRITE)) {
			Base::Select(FD_WRITE);
		}
	}

// 	int RecvBuf(char* lpBuf, int nBufLen, int* nFlags = nullptr)
// 	{
// 		std::lock_guard<std::mutex> lock(m_RecvSection);
// 		ASSERT(nFlags);
// 		int nRecvBufLen = recv_buf_.size();
// 		if (nRecvBufLen>0) {
// 			if (!(*nFlags)) {
// 				*nFlags = ParseBuf(&recv_buf_[0],nRecvBufLen);
// 				if ((*nFlags)&SOCKET_PACKET_FLAG_COMPLETE) {
// 					if (nRecvBufLen<=nBufLen) {
// 						memcpy(lpBuf,&recv_buf_[0],nRecvBufLen);
// 						recv_buf_.erase(recv_buf_.begin(),recv_buf_.begin()+nRecvBufLen);
// 					}
// 					return nRecvBufLen;
// 				}
// 			} else {
// 				if (nBufLen>=nRecvBufLen) {
// 					nBufLen = nRecvBufLen;
// 				}
// 				if (nBufLen>0) {
// 					memcpy(lpBuf,&recv_buf_[0],nBufLen);
// 					recv_buf_.erase(recv_buf_.begin(),recv_buf_.begin()+nBufLen);
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

		lpBuf = &recv_buf_[0];
		nBufLen = recv_buf_.size();

		return true;
	}
	virtual bool PrepareExpandRecvBuf(char* & lpBuf, int & nBufLen)
	{
		//std::lock_guard<std::mutex> lock(m_RecvSection);

		recv_buf_.resize(recv_buf_.size() * 2);
		lpBuf = &recv_buf_[0];
		nBufLen = recv_buf_.size();
		return true;
	}

	// virtual void OnRecvBuf(const char* lpBuf, int nBufLen, int nFlags) 
	// {
	// 	Base::OnRecvBuf(lpBuf, nBufLen, nFlags);

	// 	// std::lock_guard<std::mutex> lock(m_RecvSection);

	// 	// recv_buf_.insert(recv_buf_.end(),lpBuf,lpBuf+nBufLen);
	// }

	virtual bool PrepareSendBuf(const char* & lpBuf, int & nBufLen)
	{
		//std::unique_lock<std::mutex> lock(m_SendSection);

		int nSendBufLen = send_buf_.size();
		if (nSendBufLen>0) {
			ppr_send_buf_.swap(send_buf_);
			send_buf_.clear();
			lpBuf = ppr_send_buf_.c_str();
			nBufLen = ppr_send_buf_.size();
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
template<class TBase, class TSockAddr = SOCKADDR_IN, u_short uMaxBufSize = 1024>
class SimpleUdpSocketT : public UdpSocket<TBase,TSockAddr,uMaxBufSize>
{
	typedef UdpSocket<TBase,TSockAddr,uMaxBufSize> Base;
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
 *	@brief SimpleUdpSocketExT 定义.
 *
 *	封装SimpleUdpSocketExT，实现简单的Udp数据包网络架构，更自由的封装
 */
template<class TBase>
class SimpleUdpSocketExT : public UdpSocketEx<TBase>
{
	typedef UdpSocketEx<TBase> Base;
public:
	using typename Base::Buffer;
protected:
	std::queue<Buffer> sendbufs_;
public:
	SimpleUdpSocketExT()
	{
		
	}

	virtual ~SimpleUdpSocketExT()
	{
		
	}

	inline int Close()
	{
		int ret = Base::Close();

		while(!sendbufs_.empty())
		{
			sendbufs_.pop();
		}

		return ret;
	}

	int SendBuf(const Buffer& buf)
	{
		ASSERT(Base::IsSocket());
		sendbufs_.emplace(buf);
		if(!Base::IsSelect(FD_WRITE)) {
			Base::Select(FD_WRITE);
		}
		return 0;
	}
	
	inline int SendBuf(const char* lpBuf, int nBufLen, const SOCKADDR* lpAddr, int nAddrLen, int nFlags = 0)
	{
		return SendBuf(Buffer(lpBuf,nBufLen,lpAddr,nAddrLen,nFlags));
	}

protected:
	//
	virtual bool PrepareSendBuf(Buffer& buf)
	{
		if (!sendbufs_.empty()) {
			buf = sendbufs_.front();
			sendbufs_.pop();
			return true;
		}
		return false;
	}
};

}

#endif//_H_XSIMPLEIMPL_H_
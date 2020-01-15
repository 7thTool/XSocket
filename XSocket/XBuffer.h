#ifndef __H_XBUFFER_H__
#define __H_XBUFFER_H__

#include "XSocketDef.h"

namespace XSocket {

typedef union {
	uint64_t n64;
	struct
	{
		uint32_t n32_h;
		uint32_t n32_l;
	};
} cov64_t;

/*
* 类名：XRBuffer
* 说明：通讯内存只读处理类
*/
class XRBuffer
{
  public:
	explicit XRBuffer(const char *buf, size_t len, bool ne = false)
		: buffer_(buf), size_(len), ne_(ne), readerIndex_(0)
	{
		ASSERT(readable() == size_);
	}

	void update(const char *buf, size_t len, bool reread = false)
	{
		 buffer_ = buf;
		 size_ = len;
		 if(reread) {
		 	readerIndex_ = 0;
		 }
	}

	void swap(XRBuffer &rhs)
	{
		std::swap(buffer_, rhs.buffer_);
		std::swap(size_, rhs.size_);
		std::swap(readerIndex_, rhs.readerIndex_);
	}

	void clear()
	{
		buffer_ = nullptr;
		size_ = 0;
		readerIndex_ = 0;
	}

	void reset()
	{
		readerIndex_ = 0;
	}

	size_t size() const
	{
		return size_ - readerIndex_;
	}

	char *begin()
	{
		return const_cast<char*>(buffer_);
	}

	const char *begin() const
	{
		return buffer_;
	}

	char *end()
	{
		return const_cast<char*>(buffer_ + size_);
	}

	const char *end() const
	{
		return buffer_ + size_;
	}

	size_t readable() const
	{
		return size_ - readerIndex_;
	}

	const char *data() const
	{
		return begin() + readerIndex_;
	}

	const char *reader() const
	{
		return begin() + readerIndex_;
	}

	void retrieve(size_t len)
	{
		ASSERT(len <= readable());
		if (len < readable())
		{
			readerIndex_ += len;
		}
		else
		{
			reset();
		}
	}

	void retrieveInt64()
	{
		retrieve(sizeof(uint64_t));
	}

	void retrieveInt32()
	{
		retrieve(sizeof(uint32_t));
	}

	void retrieveInt16()
	{
		retrieve(sizeof(uint16_t));
	}

	void retrieveInt8()
	{
		retrieve(sizeof(uint8_t));
	}

	char *read(char *buf, size_t len)
	{
		peek(buf, len);
		retrieve(len);
		return buf;
	}

	template <class Y>
	Y &read(Y &rhs)
	{
		read(&rhs, sizeof(Y));
		return rhs;
	}

	uint64_t readInt64(bool ne = false)
	{
		uint64_t result = peekInt64(ne);
		retrieveInt64();
		return result;
	}

	uint32_t readInt32(bool ne = false)
	{
		uint32_t result = peekInt32(ne);
		retrieveInt32();
		return result;
	}

	uint16_t readInt16(bool ne = false)
	{
		uint16_t result = peekInt16(ne);
		retrieveInt16();
		return result;
	}

	uint8_t readInt8(bool ne = false)
	{
		uint8_t result = peekInt8();
		retrieveInt8();
		return result;
	}

	char *peek(char *buf, size_t len)
	{
		ASSERT(readable() >= len);
		::memcpy(buf, reader(), len);
		return buf;
	}
	template <class Y>
	Y &peek(Y &rhs)
	{
		peek(&rhs, sizeof(Y));
		return rhs;
	}
	uint64_t peekInt64(bool ne) const
	{
		ASSERT(readable() >= sizeof(uint64_t));
		if (ne_ && !ne)
		{
			cov64_t x;
			::memcpy(&x.n64, reader(), sizeof(uint64_t));
			x.n32_h = ntohl(x.n32_h);
			x.n32_l = ntohl(x.n32_l);
			return x.n64;
		}
		else if (!ne_ && ne)
		{
			cov64_t x;
			::memcpy(&x.n64, reader(), sizeof(uint64_t));
			x.n32_h = htonl(x.n32_h);
			x.n32_l = htonl(x.n32_l);
			return x.n64;
		}
		uint64_t x = 0;
		::memcpy(&x, reader(), sizeof(uint64_t));
		return x;
	}

	uint32_t peekInt32(bool ne) const
	{
		ASSERT(readable() >= sizeof(uint32_t));
		uint32_t x = 0;
		::memcpy(&x, reader(), sizeof(uint32_t));
		if (ne_ && !ne)
		{
			x = ntohl(x);
		}
		else if (!ne_ && ne)
		{
			x = htonl(x);
		}
		return x;
	}

	uint16_t peekInt16(bool ne) const
	{
		ASSERT(readable() >= sizeof(uint16_t));
		uint16_t x = 0;
		::memcpy(&x, reader(), sizeof(uint16_t));
		if (ne_ && !ne)
		{
			x = ntohs(x);
		}
		else if (!ne_ && ne)
		{
			x = htons(x);
		}
		return x;
	}

	uint8_t peekInt8() const
	{
		ASSERT(readable() >= sizeof(uint8_t));
		uint8_t x = *reader();
		return x;
	}

  protected:
	const char *buffer_;
	size_t size_;
	bool ne_;
	size_t readerIndex_;
};

/// x initial reserve (size) bytes read write buffer class
///
/// @code
/// +-------------------+------------------+------------------+
/// |  available bytes  |  readable bytes  |  writable bytes  |
/// |    available1     |     (CONTENT)    |    available2    |
/// +-------------------+------------------+------------------+
/// |                   |                  |                  |
/// 0      <=      readerIndex   <=   writerIndex    <=     size
///
class XBuffer : public XRBuffer
{
	typedef XRBuffer Base;
  public:
	explicit XBuffer(size_t size = 1024, bool ne = false)
		: Base(nullptr,0,ne)
	{
		innerBuffer_.reserve(size);
		ASSERT(readable() == 0);
		ASSERT(writable() == 0);
	}

	void swap(XBuffer &rhs)
	{
		Base::swap(rhs);
		innerBuffer_.swap(rhs.innerBuffer_);
	}

	void clear()
	{
		Base::clear();
		innerBuffer_.clear();
	}

	size_t writable() const
	{
		return innerBuffer_.size() - Base::size_;
	}

	size_t available() const
	{
		ASSERT(Base::size_ >= readerIndex_);
		return innerBuffer_.size() - (Base::size_ - readerIndex_);
	}

	size_t capacity() const
	{
		return innerBuffer_.capacity();
	}

	char *writer()
	{
		return begin() + Base::size_;
	}

	const char *writer() const
	{
		return begin() + Base::size_;
	}

	void ensureWritable(size_t len)
	{
		if (writable() < len)
		{
			ensureWritableBytes(len);
		}
		ASSERT(writable() >= len);
	}

	void write(size_t len)
	{
		ASSERT(len <= writable());
		Base::size_ += len;
	}

	void unwrite(size_t len)
	{
		ASSERT(len <= readable());
		Base::size_ -= len;
	}

	void write(const char *buf, size_t len)
	{
		ensureWritable(len);
		std::copy(buf, buf + len, writer());
		write(len);
	}

	void write(const void *buf, size_t len)
	{
		write(static_cast<const char *>(buf), len);
	}
	template <class Y>
	Y &write(const Y &rhs)
	{
		write(&rhs, sizeof(Y));
	}

	void writeVarint(uint64_t x, bool ne = false)
	{
		if (x < (uint8_t)0xfd)
		{
			writeInt8((uint8_t)x);
		}
		else if (x < (uint16_t)0xffff)
		{
			writeInt8((uint8_t)0xfd);
			writeInt16((uint16_t)x, ne);
		}
		else if (x < (uint32_t)0xffffffffu)
		{
			writeInt8((uint8_t)0xfe);
			writeInt32((uint32_t)x, ne);
		}
		else
		{
			writeInt8((uint8_t)0xff);
			writeInt64((uint64_t)x, ne);
		}
	}

	void writeInt64(uint64_t x, bool ne = false)
	{
		if (ne_ && !ne)
		{
			cov64_t cvt;
			cvt.n64 = x;
			cvt.n32_h = htonl(cvt.n32_h);
			cvt.n32_l = htonl(cvt.n32_l);
			x = cvt.n64;
		}
		else if (!ne_ && ne)
		{
			cov64_t cvt;
			cvt.n64 = x;
			cvt.n32_h = ntohl(cvt.n32_h);
			cvt.n32_l = ntohl(cvt.n32_l);
			x = cvt.n64;
		}
		write(&x, sizeof(uint64_t));
	}

	void writeInt32(uint32_t x, bool ne = false)
	{
		if (ne_ && !ne)
		{
			x = htonl(x);
		}
		else if (!ne_ && ne)
		{
			x = ntohl(x);
		}
		write(&x, sizeof(uint32_t));
	}

	void writeInt16(uint16_t x, bool ne = false)
	{
		if (ne_ && !ne)
		{
			x = htons(x);
		}
		else if (!ne_ && ne)
		{
			x = ntohs(x);
		}
		write(&x, sizeof(uint16_t));
	}

	void writeInt8(uint8_t x)
	{
		write(&x, sizeof(x));
	}

	// size_t prependable() const
	// {
	// 	return readerIndex_;
	// }

	// void prepend(const char *buf, size_t len)
	// {
	// 	ASSERT(len <= prependable());
	// 	readerIndex_ -= len;
	// 	std::copy(buf, buf + len, begin() + readerIndex_);
	// }

	// void prepend(const void *buf, size_t len)
	// {
	// 	prepend(static_cast<const char *>(buf), len);
	// }
	// template <class Y>
	// Y &prepend(const Y &rhs)
	// {
	// 	prepend(&rhs, sizeof(Y));
	// }

	// void prependVarint(uint64_t x, bool ne = false)
	// {
	// 	if (x < (uint8_t)0xfd)
	// 	{
	// 		prependInt8((uint8_t)x);
	// 	}
	// 	else if (x < 0xffff)
	// 	{
	// 		prependInt8((uint8_t)0xfd);
	// 		prependInt16((uint16_t)x,ne);
	// 	}
	// 	else if (x < 0xffffffffu)
	// 	{
	// 		prependInt8((uint8_t)0xfe);
	// 		prependInt32((uint32_t)x,ne);
	// 	}
	// 	else
	// 	{
	// 		prependInt8((uint8_t)0xff);
	// 		prependInt64((uint64_t)x,ne);
	// 	}
	// }

	// void prependInt64(uint64_t x, bool ne = false)
	// {
	// 	if (ne_ && !ne)
	// 	{
	// 		cov64_t cvt;
	// 		cvt.n64 = x;
	// 		cvt.n32_h = Socket::H2N(cvt.n32_h);
	// 		cvt.n32_l = Socket::H2N(cvt.n32_l);
	// 		x = x.n64;
	// 	}
	// 	else if (!ne_ && ne)
	// 	{
	// 		cov64_t cvt;
	// 		cvt.n64 = x;
	// 		cvt.n32_h = Socket::N2H(cvt.n32_h);
	// 		cvt.n32_l = Socket::N2H(cvt.n32_l);
	// 		x = x.n64;
	// 	}
	// 	prepend(&x, sizeof(uint64_t));
	// }

	// void prependInt32(uint32_t x, bool ne = false)
	// {
	// 	if (ne_ && !ne)
	// 	{
	// 		x = Socket::H2N(x);
	// 	}
	// 	else if (!ne_ && ne)
	// 	{
	// 		x = Socket::N2H(x);
	// 	}
	// 	prepend(&x, sizeof(uint32_t));
	// }

	// void prependInt16(uint16_t x, bool ne = false)
	// {
	// 	if (ne_ && !ne)
	// 	{
	// 		x = Socket::H2N(x);
	// 	}
	// 	else if (!ne_ && ne)
	// 	{
	// 		x = Socket::N2H(x);
	// 	}
	// 	prepend(&x, sizeof(uint16_t));
	// }

	// void prependInt8(uint8_t x)
	// {
	// 	prepend(&x, sizeof(x));
	// }

	void shrink()
	{
		innerBuffer_.shrink_to_fit();
		innerBuffer_.erase(innerBuffer_.begin(), innerBuffer_.begin() + Base::readerIndex_);
		Base::buffer_ = innerBuffer_.data();
		Base::size_ -= Base::readerIndex_;
		Base::readerIndex_ = 0;
	}

  protected:
	//
	void ensureWritableBytes(size_t len)
	{
		if (available() < len)
		{
			// FIXME: move readable data
			innerBuffer_.resize(Base::size_ + len);
			Base::buffer_ = innerBuffer_.data();
		}
		else
		{
			// move readable data to the front, make space inside buffer
			ASSERT(0 < Base::readerIndex_);
			size_t readableSize = readable();
			std::copy(begin() + Base::readerIndex_, begin() + Base::size_, begin());
			//Base::buffer_ = innerBuffer_.data();
			Base::size_ -= Base::readerIndex_;
			Base::readerIndex_ = 0;
			ASSERT(readableSize == readable());
		}
	}

  protected:
	std::string innerBuffer_;
};

}

#endif //__H_XBUFFER_H__

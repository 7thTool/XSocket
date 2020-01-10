#ifndef __H_XBUFFER_H__
#define __H_XBUFFER_H__

#include "XSocket.h"
#include "XCodec.h"

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

	void swap(XRBuffer &rhs)
	{
		std::swap(buffer_, rhs.buffer_);
		std::swap(size_, rhs.size_);
		std::swap(readerIndex_, rhs.readerIndex_);
	}

	void reset()
	{
		readerIndex_ = 0;
	}

	size_t size() const
	{
		return size_ - readerIndex_;
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

	uint64_t readInt64(bool ne)
	{
		uint64_t result = peekInt64(ne);
		retrieveInt64();
		return result;
	}

	uint32_t readInt32(bool ne)
	{
		uint32_t result = peekInt32(ne);
		retrieveInt32();
		return result;
	}

	uint16_t readInt16(bool ne)
	{
		uint16_t result = peekInt16(ne);
		retrieveInt16();
		return result;
	}

	uint8_t readInt8(bool ne)
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
			x.n32_h = Socket::N2H(x.n32_h);
			x.n32_l = Socket::N2H(x.n32_l);
			return x.n64;
		}
		else if (!ne_ && ne)
		{
			cov64_t x;
			::memcpy(&x.n64, reader(), sizeof(uint64_t));
			x.n32_h = Socket::H2N(x.n32_h);
			x.n32_l = Socket::H2N(x.n32_l);
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
			x = Socket::N2H(x);
		}
		else if (!ne_ && ne)
		{
			x = Socket::H2N(x);
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
			x = Socket::N2H(x);
		}
		else if (!ne_ && ne)
		{
			x = Socket::H2N(x);
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
	const char *begin() const
	{
		return buffer_;
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
class XBuffer : private std::noncopyable
{
  public:
	explicit XBuffer(size_t size = 1024)
		: buffer_(), readerIndex_(0), writerIndex_(0)
	{
		buffer_.reserve(size);
		ASSERT(readable() == 0);
		ASSERT(writable() == 0);
	}

	void swap(XBuffer &rhs)
	{
		buffer_.swap(rhs.buffer_);
		std::swap(readerIndex_, rhs.readerIndex_);
		std::swap(writerIndex_, rhs.writerIndex_);
	}

	void clear()
	{
		readerIndex_ = 0;
		writerIndex_ = 0;
	}

	size_t size() const
	{
		return writerIndex_ - readerIndex_;
	}

	size_t readable() const
	{
		return writerIndex_ - readerIndex_;
	}

	size_t writable() const
	{
		return buffer_.size() - writerIndex_;
	}

	size_t prependable() const
	{
		return readerIndex_;
	}

	size_t available() const
	{
		ASSERT(writerIndex_ >= readerIndex_);
		return buffer_.size() - (writerIndex_ - readerIndex_);
	}

	size_t capacity() const
	{
		return buffer_.capacity();
	}

	const char *data() const
	{
		return begin() + readerIndex_;
	}

	const char *reader() const
	{
		return begin() + readerIndex_;
	}

	char *writer()
	{
		return begin() + writerIndex_;
	}

	const char *writer() const
	{
		return begin() + writerIndex_;
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
			clear();
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
		writerIndex_ += len;
	}

	void unwrite(size_t len)
	{
		ASSERT(len <= readable());
		writerIndex_ -= len;
	}

	void append(const char *buf, size_t len)
	{
		ensureWritable(len);
		std::copy(buf, buf + len, writer());
		write(len);
	}

	void append(const void *buf, size_t len)
	{
		append(static_cast<const char *>(buf), len);
	}
	template <class Y>
	Y &append(const Y &rhs)
	{
		append(&rhs, sizeof(Y));
	}

	void appendVarint(uint64_t x)
	{
		if (x < (uint8_t)0xfd)
		{
			appendInt8((uint8_t)x);
		}
		else if (x < (uint16_t)0xffff)
		{
			appendInt8((uint8_t)0xfd);
			appendInt16((uint16_t)x);
		}
		else if (x < (uint32_t)0xffffffffu)
		{
			appendInt8((uint8_t)0xfe);
			appendInt32((uint32_t)x);
		}
		else
		{
			appendInt8((uint8_t)0xff);
			appendInt64((uint64_t)x);
		}
	}

	void appendInt64(uint64_t x)
	{
		append(&x, sizeof(uint64_t));
	}

	void appendInt32(uint32_t x)
	{
		append(&x, sizeof(uint32_t));
	}

	void appendInt16(uint16_t x)
	{
		append(&x, sizeof(uint16_t));
	}

	void appendInt8(uint8_t x)
	{
		append(&x, sizeof(x));
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

	uint64_t readVarint()
	{
		uint64_t result = 0;
		uint8_t space = 0;
		uint8_t mark = peekInt8();
		if (mark < (uint8_t)0xfd)
		{
			result = mark;
			retrieveInt8();
			return result;
		}
		else if (mark == (uint8_t)0xfd)
		{
			retrieveInt8();
			result = peekInt16();
			retrieveInt16();
			return result;
		}
		else if (mark == (uint8_t)0xfe)
		{
			retrieveInt8();
			result = peekInt32();
			retrieveInt32();
			return result;
		}
		else
		{
			retrieveInt8();
			result = peekInt64();
			retrieveInt64();
			return result;
		}
	}

	uint64_t readInt64()
	{
		uint64_t result = peekInt64();
		retrieveInt64();
		return result;
	}

	uint32_t readInt32()
	{
		uint32_t result = peekInt32();
		retrieveInt32();
		return result;
	}

	uint16_t readInt16()
	{
		uint16_t result = peekInt16();
		retrieveInt16();
		return result;
	}

	uint8_t readInt8()
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

	uint64_t peekInt64() const
	{
		ASSERT(readable() >= sizeof(uint64_t));
		uint64_t x = 0;
		::memcpy(&x, reader(), sizeof(uint64_t));
		return x;
	}

	uint32_t peekInt32() const
	{
		ASSERT(readable() >= sizeof(uint32_t));
		uint32_t x = 0;
		::memcpy(&x, reader(), sizeof(uint32_t));
		return x;
	}

	uint16_t peekInt16() const
	{
		ASSERT(readable() >= sizeof(uint16_t));
		uint16_t x = 0;
		::memcpy(&x, reader(), sizeof(uint16_t));
		return x;
	}

	uint8_t peekInt8() const
	{
		ASSERT(readable() >= sizeof(uint8_t));
		uint8_t x = *reader();
		return x;
	}

	void prepend(const char *buf, size_t len)
	{
		ASSERT(len <= prependable());
		readerIndex_ -= len;
		std::copy(buf, buf + len, begin() + readerIndex_);
	}

	void prepend(const void *buf, size_t len)
	{
		prepend(static_cast<const char *>(buf), len);
	}
	template <class Y>
	Y &prepend(const Y &rhs)
	{
		prepend(&rhs, sizeof(Y));
	}

	void prependVarint(uint64_t x)
	{
		if (x < (uint8_t)0xfd)
		{
			prependInt8((uint8_t)x);
		}
		else if (x < 0xffff)
		{
			prependInt8((uint8_t)0xfd);
			prependInt16((uint16_t)x);
		}
		else if (x < 0xffffffffu)
		{
			prependInt8((uint8_t)0xfe);
			prependInt32((uint32_t)x);
		}
		else
		{
			prependInt8((uint8_t)0xff);
			prependInt64((uint64_t)x);
		}
	}

	void prependInt64(uint64_t x)
	{
		prepend(&x, sizeof(uint64_t));
	}

	void prependInt32(uint32_t x)
	{
		prepend(&x, sizeof(uint32_t));
	}

	void prependInt16(uint16_t x)
	{
		prepend(&x, sizeof(uint16_t));
	}

	void prependInt8(uint8_t x)
	{
		prepend(&x, sizeof(x));
	}

	void shrink()
	{
		buffer_.shrink_to_fit();
	}

  protected:
	char *begin()
	{
		return &*buffer_.begin();
	}

	const char *begin() const
	{
		return &*buffer_.begin();
	}

	void ensureWritableBytes(size_t len)
	{
		if (available() < len)
		{
			// FIXME: move readable data
			buffer_.resize(writerIndex_ + len);
		}
		else
		{
			// move readable data to the front, make space inside buffer
			ASSERT(0 < readerIndex_);
			size_t readableSize = readable();
			std::copy(begin() + readerIndex_, begin() + writerIndex_, begin());
			readerIndex_ = 0;
			writerIndex_ = readerIndex_ + readableSize;
			ASSERT(readableSize == readable());
		}
	}

  protected:
	std::string buffer_;
	size_t readerIndex_;
	size_t writerIndex_;
};

}

#endif //__H_XBUFFER_H__

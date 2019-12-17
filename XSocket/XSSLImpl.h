#pragma once

#include "XSocketImpl.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace XSocket {

template<class TBase>
class SSLSocketT : public TBase
{
	typedef TBase Base;
public:
    SSLSocketT();
    ~SSLSocketT();
    static void setSSLCertKey(const std::string& cert, const std::string& key);
protected:
    SSL *ssl_;
    bool tcpConnected_;
    virtual int readImp(int fd, void* buf, size_t bytes);
    virtual int writeImp(int fd, const void* buf, size_t bytes);
    virtual int handleHandshake(const TcpConnPtr& con);
    static bool certKeyInited_;
};

};
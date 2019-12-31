#pragma once

#include "XSocketImpl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace XSocket {

enum {
    TLS_PROTO_TLSv1 = (1<<0)
    TLS_PROTO_TLSv1_1 = (1<<1)
    TLS_PROTO_TLSv1_2 = (1<<2)
    TLS_PROTO_TLSv1_3 =(1<<3)
    
    /* Use safe defaults */
    #ifdef TLS1_3_VERSION
    TLS_PROTO_DEFAULT = (TLS_PROTO_TLSv1_2|TLS_PROTO_TLSv1_3)
    #else
    TLS_PROTO_DEFAULT = (TLS_PROTO_TLSv1_2)
    #endif
};

typedef struct tagTLSContextConfig {
    char *cert_file;
    char *key_file;
    char *dh_params_file;
    char *ca_cert_file;
    char *ca_cert_dir;
    char *protocols;
    char *ciphers;
    char *ciphersuites;
    int prefer_server_ciphers;
} TLSContextConfig;

template<class TBase>
class SSLSocketT : public TBase
{
	typedef TBase Base;
protected:
    static SSL_CTX *tls_ctx_ = nullptr;
public:
    static void Init()
    {
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        SSL_library_init();

        if (!RAND_poll())
        {
            PRINTF("OpenSSL: Failed to seed random number generator.");
        }
    }
    static void Term()
    {
        if(tls_ctx_) {
            SSL_CTX_free(tls_ctx_);
            tls_ctx_ = nullptr;
        }
    }
    
/* Attempt to configure/reconfigure TLS. This operation is atomic and will
 * leave the SSL_CTX unchanged if fails.
 */
static int Configure(TLSContextConfig *ctx_config) {
    char errbuf[256];
    SSL_CTX *ctx = NULL;

    if (!ctx_config->cert_file) {
        PRINTF("No tls-cert-file configured!");
        goto error;
    }

    if (!ctx_config->key_file) {
        PRINTF("No tls-key-file configured!");
        goto error;
    }

    if (!ctx_config->ca_cert_file && !ctx_config->ca_cert_dir) {
        PRINTF("Either tls-ca-cert-file or tls-ca-cert-dir must be configured!");
        goto error;
    }

    ctx = SSL_CTX_new(SSLv23_method());

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

    int protocols = parseProtocolsConfig(ctx_config->protocols);
    if (protocols == -1) goto error;

    if (!(protocols & TLS_PROTO_TLSv1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    if (!(protocols & TLS_PROTO_TLSv1_1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
#ifdef SSL_OP_NO_TLSv1_2
    if (!(protocols & TLS_PROTO_TLSv1_2))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_3
    if (!(protocols & TLS_PROTO_TLSv1_3))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

    if (ctx_config->prefer_server_ciphers)
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, ctx_config->cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        PRINTF("Failed to load certificate: %s: %s", ctx_config->cert_file, errbuf);
        goto error;
    }
        
    if (SSL_CTX_use_PrivateKey_file(ctx, ctx_config->key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        PRINTF("Failed to load private key: %s: %s", ctx_config->key_file, errbuf);
        goto error;
    }
    
    if (SSL_CTX_load_verify_locations(ctx, ctx_config->ca_cert_file, ctx_config->ca_cert_dir) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        PRINTF("Failed to configure CA certificate(s) file/directory: %s", errbuf);
        goto error;
    }

    if (ctx_config->dh_params_file) {
        FILE *dhfile = fopen(ctx_config->dh_params_file, "r");
        DH *dh = NULL;
        if (!dhfile) {
            PRINTF("Failed to load %s: %s", ctx_config->dh_params_file, strerror(errno));
            goto error;
        }

        dh = PEM_read_DHparams(dhfile, NULL, NULL, NULL);
        fclose(dhfile);
        if (!dh) {
            PRINTF("%s: failed to read DH params.", ctx_config->dh_params_file);
            goto error;
        }

        if (SSL_CTX_set_tmp_dh(ctx, dh) <= 0) {
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            PRINTF("Failed to load DH params file: %s: %s", ctx_config->dh_params_file, errbuf);
            DH_free(dh);
            goto error;
        }

        DH_free(dh);
    }

    if (ctx_config->ciphers && !SSL_CTX_set_cipher_list(ctx, ctx_config->ciphers)) {
        PRINTF("Failed to configure ciphers: %s", ctx_config->ciphers);
        goto error;
    }

#ifdef TLS1_3_VERSION
    if (ctx_config->ciphersuites && !SSL_CTX_set_ciphersuites(ctx, ctx_config->ciphersuites)) {
        PRINTF("Failed to configure ciphersuites: %s", ctx_config->ciphersuites);
        goto error;
    }
#endif

    SSL_CTX_free(tls_ctx_);
    tls_ctx_ = ctx;

    return C_OK;

error:
    if (ctx) SSL_CTX_free(ctx);
    return C_ERR;
}
protected:
    SSL *ssl_;
    
    /* Process the return code received from OpenSSL>
    * Update the want parameter with expected I/O.
    * Update the connection's error state if a real error has occured.
    * Returns an SSL error code, or 0 if no further handling is required.
    */
    static int handleSSLReturnCode(int ret_value, int *want_evt) {
        if (ret_value <= 0) {
            int ssl_err = SSL_get_error(ssl_, ret_value);
            switch (ssl_err) {
                case SSL_ERROR_WANT_WRITE:
                    *want_evt |= FD_WRITE;
                    return 0;
                case SSL_ERROR_WANT_READ:
                    *want_evt |= FD_READ;
                    return 0;
                case SSL_ERROR_SYSCALL:
                    //conn->c.last_errno = errno;
                    //if (conn->ssl_error) zfree(conn->ssl_error);
                    //conn->ssl_error = errno ? zstrdup(strerror(errno)) : NULL;
                    break;
                default:
                    /* Error! */
                    // conn->c.last_errno = 0;
                    // if (conn->ssl_error) zfree(conn->ssl_error);
                    // conn->ssl_error = zmalloc(512);
                    // ERR_error_string_n(ERR_get_error(), conn->ssl_error, 512);
                    break;
            }

            return ssl_err;
        }

        return 0;
    }

public:
    SSLSocketT();
    ~SSLSocketT();

    int Send(const char* lpBuf, int nBufLen, int nFlags = 0)
	{
        int ret, ssl_err;

        ERR_clear_error();

        ret = SSL_write(ssl_, lpBuf, nBufLen);
        if (ret <= 0) {
            int want = 0;
            if (!(ssl_err = handleSSLReturnCode(ret, &want))) {
#ifdef WIN32
                SetLastError(WSAEWOULDBLOCK);
#else
                SetLastError(EAGAIN);
#endif
                return -1;
            } else {
                int nError = GetLastError();
                if (ssl_err == SSL_ERROR_ZERO_RETURN ||
                        ((ssl_err == SSL_ERROR_SYSCALL && !nError))) {
                    return 0;
                } else {
                    return -1;
                }
            }
        }

        return ret;
	}

	int Receive(char* lpBuf, int nBufLen, int nFlags = 0)
    {
        int ret, ssl_err;

        ERR_clear_error();

        ret = SSL_read(conn->ssl, lpBuf, nBufLen);
        if (ret <= 0) {
            int want = 0;
            if (!(ssl_err = handleSSLReturnCode(conn, ret, &want))) {
#ifdef WIN32
                SetLastError(WSAEWOULDBLOCK);
#else
                SetLastError(EAGAIN);
#endif
                return -1;
            } else {
                int nError = GetLastError();
                if (ssl_err == SSL_ERROR_ZERO_RETURN ||
                        ((ssl_err == SSL_ERROR_SYSCALL) && !nError)) {
                    return 0;
                } else {
                    return -1;
                }
            }
        }

        return ret;
    }
};

template<class TBase>
class SSLWorkSocketT : public SSLSocketT<TBase>
{
	typedef SSLSocketT<TBase> Base;
protected:
    byte require_auth_:1 = 0;
    byte ssl_accepted_:1 = 0;
public:
    SSLWorkSocketT();
    ~SSLWorkSocketT();

protected:
    //
    inline int handleSSLAccept(int& nErrorCode)
    {
        ERR_clear_error();

        int ret = SSL_accept(ssl_);
        if (ret <= 0) {
            int want = 0;
            if (!handleSSLReturnCode(conn, ret, &want)) {
                Base::Select(want);

                nErrorCode = 
#ifdef WIN32
                (WSAEWOULDBLOCK);
#else
                (EAGAIN);
#endif
            } else {
#ifdef WIN32
                nErrorCode = WSAENOTCONN;
#else
                nErrorCode = ENOTCONN;
#endif
            }
            return SOCKET_ERROR;
        }
        return 0;
    }

    virtual void OnRole(int nRole);
    {
        Base::OnRole(nRole);
        switch(nRole)
        {
        case SOCKET_ROLE_WORK:
        {
            ssl_ = SSL_new(tls_ctx_);
            if (!require_auth_) {
                /* We still verify certificates if provided, but don't require them.
                 */
                SSL_set_verify(ssl_, SSL_VERIFY_PEER, NULL);
            }

            SSL_set_fd(ssl_, (SOCKET)*this);
            SSL_set_accept_state(ssl_);
        }
        break;
        default:
        ASSERT(0);
        break;
        }
    }

	virtual void OnReceive(int nErrorCode)
    {
        if(nErrorCode) {
            return Base::OnReveive(nErrorCode);
        }

        ERR_clear_error();

        if(!ssl_accepted_) {
            handleSSLAccept(nErrorCode);
            if(!nErrorCode)
                ssl_accepted_ = true;
        }
        Base::OnReveive(nErrorCode);
    }

	virtual void OnSend(int nErrorCode)
    {
        if(nErrorCode) {
            return Base::OnSend(nErrorCode);
        }

        if(!ssl_accepted_) {
            handleSSLAccept(nErrorCode);
            if(!nErrorCode)
                ssl_accepted_ = true;
        }
        Base::OnSend(nErrorCode);
    }
};


template<class TBase>
class SSLConnectSocketT : public SSLSocketT<TBase>
{
	typedef SSLSocketT<TBase> Base;
public:
    SSLConnectSocketT();
    ~SSLConnectSocketT();

protected:
    //
    inline int handleSSLConnect(int& nErrorCode)
    {
        ERR_clear_error();

        int ret = SSL_connect(ssl_);
        if (ret <= 0) {
            int want = 0;
            if (!handleSSLReturnCode(conn, ret, &want)) {
                Base::Select(want);

                /* Avoid hitting UpdateSSLEvent, which knows nothing
                 * of what SSL_connect() wants and instead looks at our
                 * R/W handlers.
                 */
                nErrorCode = 
#ifdef WIN32
                (WSAEWOULDBLOCK);
#else
                (EAGAIN);
#endif
            } else {
#ifdef WIN32
                nErrorCode = WSAENOTCONN;
#else
                nErrorCode = ENOTCONN;
#endif
            }
            return SOCKET_ERROR;
        }
        return 0;
    }

    virtual void OnRole(int nRole);
    {
        Base::OnRole(nRole);
        switch(nRole)
        {
        case SOCKET_ROLE_CONNECT:
        {
            ssl_ = SSL_new(tls_ctx_);

            SSL_set_fd(ssl_, (SOCKET)*this);
        }
        break;
        default:
        ASSERT(0);
        break;
        }
    }

    virtual void OnReceive(int nErrorCode)
    {
        if(nErrorCode) {
            return Base::OnReveive(nErrorCode);
        }

        if(!Base::IsConnect()) {
            handleSSLConnect(nErrorCode);
            Base::OnConnect(nErrorCode);
        } else {
            Base::OnReveive(nErrorCode);
        }
    }

	virtual void OnSend(int nErrorCode)
    {
        if(nErrorCode) {
            return Base::OnSend(nErrorCode);
        }

        if(!Base::IsConnect()) {
            handleSSLConnect(nErrorCode);
            Base::OnConnect(nErrorCode);
        } else {
            Base::OnSend(nErrorCode);
        }
    }

    virtual void OnConnect(int nErrorCode)
    {
        if (nErrorCode) {
            return Base::OnConnect(nErrorCode);
        }

        ASSERT(!Base::IsConnect());
        handleSSLConnect(nErrorCode);
        Base::OnConnect(nErrorCode);
    }
};

};
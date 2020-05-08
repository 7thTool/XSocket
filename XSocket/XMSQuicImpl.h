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
#ifndef _H_XMSQUIC_IMPL_H_
#define _H_XMSQUIC_IMPL_H_

#include "XBuffer.h"
#include "XCodec.h"
#include "XSocketImpl.h"
#include <msquichelper.h>

namespace XSocket { namespace msquic {

template<class T, class TService, class TBase = SocketEx>
class Connection : public XSocket::TaskSocketT<TBase>
{
    typedef TBase Base;
public:
    Connection() {}

    //connect
    bool Open(const char* ServerName
    , uint16_t ServerPort // Host byte order
    )
    {
        QUIC_STATUS Status;
        if (QUIC_FAILED(Status = api()->ConnectionOpen(session(), [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            T* pT = reinterpret_cast<T*>(Context);
            if(pT) {
                return pT->OnEvent(*Event);
            }
            return QUIC_STATUS_SUCCESS;
        }, nullptr, &conn_))) {
            PRINTF("ConnectionOpen failed, 0x%x!", Status);
            return false;
        }

        /*if (GetValue(argc, argv, "unsecure")) {
            const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
            if (QUIC_FAILED(Status = MsQuic->SetParam(
                    Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                    sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
                printf("SetParam(QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS) failed, 0x%x!\n", Status);
                goto Error;
            }
        }*/

        PRINTF("[%s:%d][%p] Connecting...", ServerName, ServerPort, conn_);

        if (QUIC_FAILED(Status = api()->ConnectionStart(conn_, AF_UNSPEC, ServerName, ServerPort))) {
            PRINTF("ConnectionStart failed, 0x%x!", Status);
            return false;
        }
        return true;
    }

    //listener
	SOCKET Attach(TService* srv, const QUIC_NEW_CONNECTION_INFO& info, HQUIC conn, int Role = SOCKET_ROLE_NONE)
    {
        srv_ = srv;
        info_ = info;
        conn_ = conn;
        SOCKET ret = Attach((SOCKET)conn, Role);
        api()->SetCallbackHandler(conn_, (void*)[](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            T* pT = reinterpret_cast<T*>(Context);
            if(pT) {
                return pT->OnEvent(*Event);
            }
            return QUIC_STATUS_SUCCESS;
        }, this);
        return ret;
    }

    void Close() {
        if (conn_ != nullptr) {
            api()->ConnectionClose(conn_);
            conn_ = nullptr;
        }
	}

    inline HQUIC connection() { return conn_; }
    inline QUIC_API_TABLE* api() { return srv_->api(); }
    inline HQUIC registration() { return srv_->registration(); }
    inline HQUIC session() { return srv_->session(); }
    inline TService* srv() { return srv_; }

protected:
    //
    QUIC_STATUS OnEvent(const QUIC_CONNECTION_EVENT& evt)
    {
        switch (evt.Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            //printf("[conn][%p] Connected\n", Connection);
            //ClientSend(Connection);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            //printf("[conn][%p] Shutdown\n", Connection);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            //printf("[conn][%p] All done\n", Connection);
            Close();
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: //listener
            //printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
            //MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, nullptr);
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

private:
    TService* srv_ = nullptr;
    QUIC_NEW_CONNECTION_INFO info_ = {0};
    HQUIC conn_ = nullptr;
};

template<class T, class TConnection>
class Stream
{
public:
    typedef typename TConnection Connection;

    Stream(TConnection* conn):conn_(conn){ 

    }

    bool Open()
    {
        QUIC_STATUS Status;
        HQUIC Stream = nullptr;
        uint8_t* SendBufferRaw;
        QUIC_BUFFER* SendBuffer;
        if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, nullptr, &Stream))) {
            printf("StreamOpen failed, 0x%x!\n", Status);
            goto Error;
        }

        printf("[strm][%p] Starting...\n", Stream);

        if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
            printf("StreamStart failed, 0x%x!\n", Status);
            MsQuic->StreamClose(Stream);
            goto Error;
        }

        SendBufferRaw = (uint8_t*)QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + SendBufferLength);
        if (SendBufferRaw == nullptr) {
            printf("SendBuffer allocation failed!\n");
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
        SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
        SendBuffer->Length = SendBufferLength;

        printf("[strm][%p] Sending data...\n", Stream);

        if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
            printf("StreamSend failed, 0x%x!\n", Status);
            QUIC_FREE(SendBufferRaw);
            goto Error;
        }
    }

    void Attach()
    {
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, this);
    }

    void Close()
    {
        if (stream_ != nullptr) {
            api->ConnectionShutdown(connection(), QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }

    inline HQUIC stream() { return stream_; }
    inline HQUIC connection() { return conn_->connection(); }
    inline QUIC_API_TABLE* api() { return conn_->api(); }
    inline HQUIC registration() { return conn_->registration(); }
    inline HQUIC session() { return conn_->session(); }
    inline Connection* conn() { return conn_; }

protected:
    static QUIC_STATUS Callback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event)
    {
        T* pT = reinterpret_cast<T*>(Context);
        if(pT) {
           return pT->OnEvent(*Event);
        }
        return QUIC_STATUS_SUCCESS;
    }
    QUIC_STATUS OnEvent(const QUIC_STREAM_EVENT& evt)
    {
        switch (evt.Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            QUIC_FREE(Event->SEND_COMPLETE.ClientContext);
            printf("[strm][%p] Data sent\n", Stream);
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[strm][%p] Data received\n", Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            printf("[strm][%p] Peer shutdown\n", Stream);
            ServerSend(Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("[strm][%p] Peer aborted\n", Stream);
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[strm][%p] All done\n", Stream);
            MsQuic->StreamClose(Stream);
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

private:
    Connection* conn_ = nullptr;
    HQUIC stream_ = nullptr;
};

template<class T, class TConnectionSet>
class ServerClientBase : public XSocket::SocketManagerT<TConnectionSet>
{
    typedef XSocket::SocketManagerT<TConnectionSet> Base;
public:
    typedef TConnectionSet ConnectionSet;
    typedef typename Base::Socket Connection;

    static bool Init() {
        QuicPlatformSystemLoad();

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        if (QUIC_FAILED(Status = QuicPlatformInitialize())) {
            PRINTF("QuicPlatformInitialize failed, 0x%x!", Status);
            QuicPlatformSystemUnload();
            return false;
        }
        return true;
    }
    static void Term() {
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
    }
    
    ServerClientBase(int nMaxConnectionSetCount):Base(nMaxConnectionSetCount) {}

    inline QUIC_API_TABLE* api() { return api_; }
    inline HQUIC registration() { return Registration; }
    inline HQUIC session() { return Session; }

    bool Open(const QUIC_REGISTRATION_CONFIG& RegConfig, const QUIC_BUFFER& Alpn)
    {
        if (QUIC_FAILED(Status = MsQuicOpen(&api_))) {
            PRINTF("MsQuicOpen failed, 0x%x!", Status);
            return false;
        }

        if (QUIC_FAILED(Status = api()->RegistrationOpen(&RegConfig, &Registration))) {
            PRINTF("RegistrationOpen failed, 0x%x!", Status);
            return false;
        }

        if (QUIC_FAILED(Status = api()->SessionOpen(Registration, &Alpn, 1, nullptr, &Session))) {
            PRINTF("SessionOpen failed, 0x%x!", Status);
            return false;
        }

        if (QUIC_FAILED(Status = api()->SetParam(
                Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_IDLE_TIMEOUT,
                sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
            PRINTF("SetParam(QUIC_PARAM_SESSION_IDLE_TIMEOUT) failed, 0x%x!", Status);
            return false;
        }

        return true;
    }

    void Close()
    {
        if (api_ != nullptr) {
            if (Session != nullptr) {
                api()->SessionClose(Session); // Waits on all connections to be cleaned up.
            }
            if (Registration != nullptr) {
                api()->RegistrationClose(Registration);
            }
            MsQuicClose(api_);
        }
    }

private:
    QUIC_API_TABLE* api_ = nullptr;
    HQUIC Registration = nullptr;
    HQUIC Session = nullptr;
};

template<class T, class TConnection>
class Server : public ServerClientBase<T,TConnection>
{
    typedef ServerClientBase<T,TConnection> Base;
public:
    using Base::Base;
    
    bool Open(const QUIC_REGISTRATION_CONFIG& RegConfig, const QUIC_BUFFER& Alpn, const u_short UdpPort, const char* Cert, const char* KeyFile)
    {
        if(!Base::Open(RegConfig,Alpn)) {
            return false;
        }
        QUIC_STATUS Status;
        const uint16_t PeerStreamCount = 1;
        HQUIC Listener = nullptr;

        QUIC_ADDR Address = {};
        QuicAddrSetFamily(&Address, AF_UNSPEC);
        QuicAddrSetPort(&Address, UdpPort);

        //if (TryGetValue(argc, argv, "cert_hash", &Cert)) {
        if(Cert && !KeyFile) {
            SecurityConfig = GetSecConfigForThumbprint(api(), Registration, Cert);
            if (SecurityConfig == nullptr) {
                PRINTF("Failed to load certificate from hash!");
                return false;
            }
        //} else if (TryGetValue(argc, argv, "cert_file", &Cert) &&
        //    TryGetValue(argc, argv, "key_file", &KeyFile)) {
        } else if (Cert && KeyFile) {
            SecurityConfig = GetSecConfigForFile(api(), Registration, KeyFile, Cert);
            if (SecurityConfig == nullptr) {
                PRINTF("Failed to load certificate from file!");
                return false;
            }
        } else {
            PRINTF("Must specify '-cert_hash' or 'cert_file'!");
            return false;
        }

        if (QUIC_FAILED(Status = MsQuic->SetParam(
                Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT,
                sizeof(PeerStreamCount), &PeerStreamCount))) {
            PRINTF("SetParam(QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT) failed, 0x%x!", Status);
            return false;
        }

        if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Session, [](HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
            T* pT = reinterpret_cast<T*>(Context);
            if(pT) {
                return pT->OnEvent(*Event);
            }
            return QUIC_STATUS_SUCCESS;
        }, this, &Listener))) {
            PRINTF("ListenerOpen failed, 0x%x!", Status);
            return false;
        }

        if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Address))) {
            PRINTF("ListenerStart failed, 0x%x!", Status);
            return false;
        }
        return true;
    }

    void Close()
    {
        if (Listener != nullptr) {
            api()->ListenerClose(Listener);
        }
        api()->SecConfigDelete(SecurityConfig);
        Base::Close();
    }
protected:
    //
    QUIC_STATUS OnEvent(const QUIC_LISTENER_EVENT& evt)
    {
        switch (evt.Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            evt.NEW_CONNECTION.SecurityConfig = SecurityConfig;
            auto conn = std::make_shared<Connection>();
            conn->Attach(static_cast<T*>(this), *evt.NEW_CONNECTION.Info, evt.NEW_CONNECTION.Connection);
            AddSocket(conn);
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

private:
    QUIC_SEC_CONFIG* SecurityConfig = nullptr;
    HQUIC Listener = nullptr;
};

template<class T, class TConnection>
class Client : public ServerClientBase<T,TConnection>
{
    typedef ServerClientBase<T,TConnection> Base;
public:
    using Base::Base;
    
    bool Open(const QUIC_REGISTRATION_CONFIG& RegConfig, const QUIC_BUFFER& Alpn)
    {
        if(!Base::Open(RegConfig,Alpn)) {
            return false;
        }
        return true;
    }

    void Close()
    {
        Base::Close();
    }

protected:
    //

private:
};

} }  // namespace XSocket::msquic

#endif  //_H_XMSQUIC_IMPL_H_
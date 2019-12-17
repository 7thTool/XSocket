# XSocket
简单的Modern C++ Socket跨平台可伸缩实现，支持Windows、Linux、Mac OS、Android、iOS全平台的Tcp/Udp套接字客户端和服务端模板（泛型）封装（select/完成端口/epoll），在此基础上支持SOCK4/4a/SOCK5/Http代理，支持Http/WebSocket协议，支持Http /2协议，支持Quic协议，支持Http Quic(Http /3)协议等

平台：Windows、Linux、Mac OS、Android、iOS全平台
套接字：Tcp/Udp的select/完成端口/epoll模型封装
自定义：只需实现Parse接口，即可接入自定义协议
代理：SOCK4/4a/SOCK5/Http代理
HTTP：支持Http/WebSocket协议
HTTP2: 支持Http /2协议
QUIC: 支持Quic协议
HTTP3: 支持Http Quic(Http /3)协议


#ifndef _H_SAMPLES_H_
#define _H_SAMPLES_H_

#define USE_ZLIB 1
#define USE_OPENSSL 0
#define USE_WEBSOCKET 0

#define USE_IPV6 0

//UDP构建可靠数据传输
//要使用UDP来构建可靠的面向连接的数据传输，就要实现类似于TCP协议的超时重传，有序接受，应答确认，滑动窗口流量控制等机制，
//等于说要在传输层的上一层（或者直接在应用层）实现TCP协议的可靠数据传输机制，比如使用UDP数据包+序列号，UDP数据包+时间戳等方法，在服务器端进行应答确认机制，
//这样就会保证不可靠的UDP协议进行可靠的数据传输。
#define USE_UDP 1
#if USE_UDP
#define USE_MANAGER 0
#else
#define USE_MANAGER 1
#endif//

#define DEFAULT_CLIENT_COUNT 1

#endif//_H_SAMPLES_H_
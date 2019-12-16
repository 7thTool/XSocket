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

#ifndef _H_XHTTP_PROXY_IMPL_H_
#define _H_XHTTP_PROXY_IMPL_H_

#include "XSocketImpl.h"
#include "XProxyImpl.h"
#include "XHttpImpl.h"

namespace XSocket {

enum PROXY_RESULT
{
ALLOW,
DENY,
REDIRECT,
BANDLIM,
NOBANDLIM,
COUNTIN,
NOCOUNTIN,
COUNTOUT,
NOCOUNTOUT,
CONNLIM,
NOCONNLIM,
};

enum PROXY_COMMAND
{
CONNECT = 	0x00000001,
BIND =		0x00000002,
UDPASSOC =	0x00000004,
ICMPASSOC =	0x00000008	/* reserved */,
HTTP_GET =	0x00000100,
HTTP_PUT =	0x00000200,
HTTP_POST =	0x00000400,
HTTP_HEAD =	0x00000800,
HTTP_CONNECT =	0x00001000,
HTTP_OTHER =	0x00008000,
HTTP =		0x0000EF00	/* all except HTTP_CONNECT */,
HTTPS =		HTTP_CONNECT,
FTP_GET =		0x00010000,
FTP_PUT =		0x00020000,
FTP_LIST =	0x00040000,
FTP_DATA =	0x00080000,
FTP =		0x000F0000,
DNSRESOLVE =	0x00100000,
ADMIN =		0x01000000,
};

struct ProxyParam
{
	unsigned short http_major;
	unsigned short http_minor;
	unsigned short status_code;
	unsigned int method;
	int transparent = 0;
	enum {
		UNKNOWN = -1,
		URL,
		SCHEMA,
		HOST,
		PORT,
  		//PATH,
  		//QUERY,
  		//FRAGMENT,
		USERINFO,
		AUTHINFO,
		PROXY_AUTHINFO,
		USERNAME,
		PASSWORD,
		CONNECTION,
		PROXY_CONNECTION,
		EXPECT,
		CONTENT_LENGTH,
		COUNT
	} eat = UNKNOWN;
	const char* at[COUNT] = { 0 };
	size_t length[COUNT] = { 0 };
};

const char * proxy_stringtable[] = {
/* 0 */	"HTTP/1.0 400 Bad Request\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2></body></html>\r\n",

/* 1 */	"HTTP/1.0 502 Bad Gateway\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed</h3></body></html>\r\n",

/* 2 */	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>You have exceeded your traffic limit</h3></body></html>\r\n",

/* 3 */	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>Recursion detected</h3></body></html>\r\n",

/* 4 */	"HTTP/1.0 501 Not Implemented\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>501 Not Implemented</title></head>\r\n"
	"<body><h2>501 Not Implemented</h2><h3>Required action is not supported by proxy server</h3></body></html>\r\n",

/* 5 */	"HTTP/1.0 502 Bad Gateway\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2><h3>Failed to connect parent proxy</h3></body></html>\r\n",

/* 6 */	"HTTP/1.0 500 Internal Error\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>500 Internal Error</title></head>\r\n"
	"<body><h2>500 Internal Error</h2><h3>Internal proxy error during processing your request</h3></body></html>\r\n",

/* 7 */	"HTTP/1.0 407 Proxy Authentication Required\r\n"
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>\r\n",

/* 8 */	"HTTP/1.0 200 Connection established\r\n\r\n",

/* 9 */	"HTTP/1.0 200 Connection established\r\n"
	"Content-Type: text/html\r\n\r\n",

/* 10*/	"HTTP/1.0 404 Not Found\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>404 Not Found</title></head>\r\n"
	"<body><h2>404 Not Found</h2><h3>File not found</body></html>\r\n",
	
/* 11*/	"HTTP/1.0 403 Forbidden\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>403 Access Denied</title></head>\r\n"
	"<body><h2>403 Access Denied</h2><h3>Access control list denies you to access this resource</body></html>\r\n",

/* 12*/	"HTTP/1.0 407 Proxy Authentication Required\r\n"
#ifndef NOCRYPT
	"Proxy-Authenticate: NTLM\r\n"
#endif
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>\r\n",

/* 13*/	"HTTP/1.0 407 Proxy Authentication Required\r\n"
	"Connection: keep-alive\r\n"
	"Content-Length: 0\r\n"
	"Proxy-Authenticate: NTLM ",

/* 14*/	"HTTP/1.0 403 Forbidden\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<pre>",

/* 15*/	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>Your request violates configured policy</h3></body></html>\r\n",

/* 16*/	"HTTP/1.0 401 Authentication Required\r\n"
	"WWW-Authenticate: Basic realm=\"FTP Server\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>401 FTP Server requires authentication</title></head>\r\n"
	"<body><h2>401 FTP Server requires authentication</h2><h3>This FTP server rejects anonymous access</h3></body></html>\r\n",

/* 17*/ "HTTP/1.1 100 Continue\r\n"
	"\r\n",

	NULL
};

/*!
 *	@brief ProxydSocketT 模板定义.
 *
 *	封装ProxydSocketT，实现代理服务端逻辑
 */
template<class TBase>
class HttpProxydSocketT : public HttpSocket<TBase>
{
	typedef ProxydSocketT<TBase> This;
	typedef TBase Base;
protected:
	byte m_ProxyType:3; //代理类型
	byte m_ProxyState:5;	//代理状态
	SOCKADDR_IN ProxyAddr_ = {0}; //代理地址

public:
	ProxydSocketT():m_ProxyType(PROXYTYPE_NONE),m_ProxyState(PROXY_STATE_NONE)
	{
	}

	inline bool IsProxyUserRequired() { return false; }
	inline bool IsProxyAuthRequired() { return false; }
	inline bool IsProxyNTLMRequired() { return false; }

	inline bool IsProxyOK()
	{
		return m_ProxyType!=PROXYTYPE_NONE && m_ProxyState==PROXY_STATE_OK;
	}

	inline bool IsInProxy()
	{
		return m_ProxyType!=PROXYTYPE_NONE && m_ProxyState!=PROXY_STATE_OK;
	}

	inline int Close()
	{
		int ret = Base::Close();
		m_ProxyType = PROXYTYPE_NONE;
		m_ProxyState = PROXY_STATE_NONE;
		return ret;
	}

protected:
	//
	
int scanaddr(const unsigned char *s, unsigned long * ip, unsigned long * mask) {
	unsigned d1, d2, d3, d4, m;
	int res;
	if ((res = sscanf((char *)s, "%u.%u.%u.%u/%u", &d1, &d2, &d3, &d4, &m)) < 4) return 0;
	if(mask && res == 4) *mask = 0xFFFFFFFF;
	else if (mask) *mask = htonl(0xFFFFFFFF << (32 - m));
	*ip = htonl ((d1<<24) ^ (d2<<16) ^ (d3<<8) ^ d4);
	return res;
}

RESOLVFUNC resolvfunc = nullptr;
#ifdef NOIPV6
unsigned long getip(unsigned char *name){
	unsigned long retval;
	int i;
	int ndots = 0;
	struct hostent *hp=NULL;
	RESOLVFUNC tmpresolv;

#ifdef GETHOSTBYNAME_R
	struct hostent he;
	char ghbuf[1024];
#define gethostbyname(NAME) my_gethostbyname(NAME, ghbuf, &he)
#endif

	if(strlen((char *)name)>255)name[255] = 0;
	for(i=0; name[i]; i++){
		if(name[i] == '.'){
			if(++ndots > 3) break;
			continue;
		}
		if(name[i] <'0' || name[i] >'9') break;
	}
	if(!name[i] && ndots == 3){
		if(scanaddr(name, &retval, NULL) == 4){
			return retval;
		}
	}
	if((tmpresolv=resolvfunc)){
		if((*tmpresolv)(AF_INET, name, (unsigned char *)&retval)) return retval;
		if(conf.demanddialprog) system(conf.demanddialprog);
		return (*tmpresolv)(AF_INET, name, (unsigned char *)&retval)?retval:0;
	}
#if !defined(_WIN32) && !defined(GETHOSTBYNAME_R)
	if(!ghbn_init){
		pthread_mutex_init(&gethostbyname_mutex, NULL);
		ghbn_init++;
	}
	pthread_mutex_lock(&gethostbyname_mutex);
#endif
	hp=gethostbyname((char *)name);
	if (!hp && conf.demanddialprog) {
		system(conf.demanddialprog);
		hp=gethostbyname((char *)name);
	}
	retval = hp?*(unsigned long *)hp->h_addr:0;
#if !defined(_WIN32) && !defined(GETHOSTBYNAME_R)
	pthread_mutex_unlock(&gethostbyname_mutex);
#endif
#ifdef GETHOSTBYNAME_R
#undef gethostbyname
#endif
	return retval;
}
#endif

unsigned long getip46(int family, unsigned char *name,  struct sockaddr *sa){
#ifndef NOIPV6
	int ndots=0, ncols=0, nhex=0;
	struct addrinfo *ai, hint;
	int i;
        RESOLVFUNC tmpresolv;

	if(!sa) return 0;
	if(!family) {
		family = 4;
#else
		((struct sockaddr_in *)sa)->sin_family = AF_INET;
		return (((struct sockaddr_in *)sa)->sin_addr.s_addr = getip(name))? AF_INET:0;
#endif
#ifndef NOIPV6
	}
	for(i=0; name[i]; i++){
		if(name[i] == '.'){
			if(++ndots > 3) {
				break;
			}
		}
		else if(name[i] == ':'){
			if(++ncols > 7) {
				break;
			}
		}
		else if(name[i] == '%' || (name[i] >= 'a' && name[i] <= 'f') || (name[i] >= 'A' && name[i] <= 'F')){
			nhex++;
		}
		else if(name[i] <'0' || name[i] >'9') {
			break;
		}
	}
	if(!name[i]){
		if(ndots == 3 && ncols == 0 && nhex == 0){
			*SAFAMILY(sa)=(family == 6)?AF_INET6 : AF_INET;
			return inet_pton(*SAFAMILY(sa), (char *)name, SAADDR(sa))? *SAFAMILY(sa) : 0; 
		}
		if(ncols >= 2) {
			*SAFAMILY(sa)=AF_INET6;
			return inet_pton(AF_INET6, (char *)name, SAADDR(sa))?(family==4? 0:AF_INET6) : 0;
		}
	}
	if((tmpresolv = resolvfunc)){
		int f = (family == 6 || family == 64)?AF_INET6:AF_INET;
		*SAFAMILY(sa) = f;
		if(tmpresolv(f, name, SAADDR(sa))) return f;
		if(family == 4 || family == 6) return 0;
		f = (family == 46)? AF_INET6 : AF_INET;
		*SAFAMILY(sa) = f;
		if(tmpresolv(f, name, SAADDR(sa))) return f;
		return 0;
	}
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = (family == 6 || family == 64)?AF_INET6:AF_INET;
	if (getaddrinfo((char *)name, NULL, &hint, &ai)) {
		if(family == 64 || family == 46){
			hint.ai_family = (family == 64)?AF_INET:AF_INET6;
			if (getaddrinfo((char *)name, NULL, &hint, &ai)) return 0;
		}
		else return 0;
	}
	if(ai){
		if(ai->ai_addr->sa_family == AF_INET || ai->ai_addr->sa_family == AF_INET6){
			*SAFAMILY(sa)=ai->ai_addr->sa_family;
			memcpy(SAADDR(sa), SAADDR(ai->ai_addr), SAADDRLEN(ai->ai_addr));
			freeaddrinfo(ai);
			return *SAFAMILY(sa);
		}
		freeaddrinfo(ai);
	}
	return 0;
#endif
}

	int ReceiveProxy(const char* lpBuf, int & nBufLen)
	{
		if (m_ProxyType==0) {
			switch(lpBuf[0])
			{
			case 0x04:
			{
#if 1
				char hex[1024] = {0};
				int hexlen = 1024;
				HexEncode((const byte*)lpBuf, nBufLen, hex, &hexlen);
				PRINTF("%.*s\n", hexlen, hex);
#endif//
				// SOCKS 4
				// ---------------------------------------------------------------------------
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
				//            +----+----+----+----+----+----+----+----+----+----+....+----+
				//# of bytes:   1    1      2              4           variable       1
				if(nBufLen < 9) {
					return SOCKET_PACKET_FLAG_PENDING;
				} else {
					//byte CD = lpBuf[1];
					u_short port = *(u_short*)&lpBuf[2];
					u_long ip = *(u_long*)&lpBuf[4];
					if(ip != 0) {
						m_ProxyType = PROXYTYPE_SOCKS4;
						OnProxy(ip, port);
						return SOCKET_PACKET_FLAG_COMPLETE;
					} else if(lpBuf[nBufLen-1]==0 /* && lpBuf[4] = 0 && lpBuf[5] = 0 && lpBuf[6] = 0 && lpBuf[7] != 0*/) {
						m_ProxyType = PROXYTYPE_SOCKS4A;
						const char* host = (const char*)(lpBuf+9);
						OnProxy(host, port);
						return SOCKET_PACKET_FLAG_COMPLETE;
					} else {
						return SOCKET_PACKET_FLAG_PENDING;
					}
				}
			}
			break;
			case 0x05:
			{
				m_ProxyType = PROXYTYPE_SOCKS5;
			}
			break;
			default:
			{
				/*if(nBufLen < 4) {
					return SOCKET_PACKET_FLAG_PENDING;
				}
				if(memcmp(lpBuf + nBufLen - 4, "\r\n\r\n", 4) == 0) {
					if(strncmp(lpBuf, "CONNECT", 7) == 0) {
						char* next = (char*)lpBuf + 7;
						char* host = strchr(next,' ');
						if(!host) break;
						host++; next = host;
						char* port = strchr(next,':');
						if(!port) break;
						*port = 0; port++; next = port;
						next = strchr(next,' ');
						if(!next) break;
						*next = 0;
						OnProxy(host, std::atoi(port));
						return SOCKET_PACKET_FLAG_COMPLETE;
					}
				}*/
				ProxyParam param;
				http_parser_settings settings = {0};
				http_parser parser = {0};
				//thread_local bool http_parser_thread_init = false;
				//if(!http_parser_thread_init) {
				//	http_parser_thread_init = true;
					PRINTF("http_parser_thread_init\n");
					settings.on_message_begin = [](http_parser *parser) { return 0; };
					settings.on_url = [](http_parser* parser, const char *at, size_t length) { 
						PRINTF("on_url %.*s\n", length, at);
						ProxyParam* param = (ProxyParam*)parser->data;
						if(!param) {
							return 0;
						}
						param->at[ProxyParam::URL] = at;
						param->length[ProxyParam::URL] = length;
						struct http_parser_url url_parser;
						http_parser_url_init(&url_parser);
						if(0 == http_parser_parse_url(at, length, 1, &url_parser)) {
							if(url_parser.field_set & (1 << UF_SCHEMA)) {
								param->at[ProxyParam::SCHEMA] = at + url_parser.field_data[UF_SCHEMA].off;
								param->length[ProxyParam::SCHEMA] = url_parser.field_data[UF_SCHEMA].len;
							}
							if(url_parser.field_set & (1 << UF_PORT)) {
								param->at[ProxyParam::PORT] = at + url_parser.field_data[UF_PORT].off;
								param->length[ProxyParam::PORT] = url_parser.field_data[UF_PORT].len;
							}
							if(url_parser.field_set & (1 << UF_HOST)) {
								param->at[ProxyParam::HOST] = at + url_parser.field_data[UF_HOST].off;
								param->length[ProxyParam::HOST] = url_parser.field_data[UF_HOST].len;
							}
							if(url_parser.field_set & (1 << UF_USERINFO)) {
								param->at[ProxyParam::USERINFO] = at + url_parser.field_data[UF_USERINFO].off;
								param->length[ProxyParam::USERINFO] = url_parser.field_data[UF_USERINFO].len;
							}
						}
						return 0;
					};
					settings.on_status = [](http_parser* parser, const char *at, size_t length) {  
						PRINTF("on_status %.*s\n", length, at);
						return 0; 
					};
					settings.on_header_field = [](http_parser* parser, const char *at, size_t length) {  
						PRINTF("on_header_field %.*s ", length, at);
						ProxyParam* param = (ProxyParam*)parser->data;
						if(!param) {
							return 0;
						}
						if(strnicmp(at, "Host", length) == 0) {
							param->eat = ProxyParam::HOST;
						} 
						else if(strnicmp(at, "Authorization", length) == 0) {
							param->eat = ProxyParam::AUTHINFO;
						} 
						else if(strnicmp(at, "Proxy-Authorization", length) == 0) {
							param->eat = ProxyParam::PROXY_AUTHINFO;
						} 
						else if(strnicmp(at, "Proxy-Connection", length) == 0) {
							param->eat = ProxyParam::PROXY_CONNECTION;
						} 
						else if(strnicmp(at, "Connection", length) == 0) {
							param->eat = ProxyParam::CONNECTION;
						} 
						else if(strnicmp(at, "Expect", length) == 0) {
							param->eat = ProxyParam::EXPECT;
						}  
						else if(strnicmp(at, "Content-Length", length) == 0) {
							param->eat = ProxyParam::CONTENT_LENGTH;
						} else {
							param->eat = ProxyParam::UNKNOWN;
						}
						return 0; 
					};
					settings.on_header_value = [](http_parser* parser, const char *at, size_t length) {  
						PRINTF("%.*s\n", length, at);
						ProxyParam* param = (ProxyParam*)parser->data;
						if(!param) {
							return 0;
						}
						if(param->eat >= 0 && param->eat < ProxyParam::COUNT) {
							switch(param->eat)
							{
							case ProxyParam::HOST:
							{
								param->at[param->eat] = at;
								const char* port = strchr(at,':');
								if(port) {
									param->length[param->eat] = port - at;
									port++;
									param->at[ProxyParam::PORT] = port;
									param->length[ProxyParam::PORT] = length - 1 - param->length[param->eat];
								} else {
									param->length[param->eat] = length;
								}
							}
							break;
							case ProxyParam::PROXY_AUTHINFO:
							{
								param->at[param->eat] = at;
								param->length[param->eat] = length;
								const char* sb = at;
								int slen = length;
								if(!strnicmp((char *)sb, "basic", 5)) {
									sb+=5; slen-=5;
									while(isspace(*sb))sb++;
									if(!Base64Decode(sb, slen, (byte*)sb, &slen)) {
										break;
									}
									const char* & user = param->at[ProxyParam::USERNAME];
									size_t & user_len = param->length[ProxyParam::USERNAME];
									user = sb;
									sb = strnchr(sb, slen, ':');
									if(sb) {
										const char* & pwd = param->at[ProxyParam::PASSWORD];
										size_t & pwd_len = param->length[ProxyParam::PASSWORD];
										pwd = sb + 1;
										pwd_len = slen - user_len - 1;
										//param->pwtype = 0;
									}
								}
							}
							break;
							default:
							{
								param->at[param->eat] = at;
								param->length[param->eat] = length;
							}
							break;
							}
						}
						return 0; 
					};
					settings.on_headers_complete = [](http_parser *parser) { return 0; };
					settings.on_body = [] (http_parser* parser, const char *at, size_t length) {  
						PRINTF("on_body %.*s\n", length, at);
						return 0; 
					};
					settings.on_message_complete = [](http_parser* parser) { return 0; };
				//}
				http_parser_init(&parser, HTTP_REQUEST);
				parser.data = &param;
				int nParsed = http_parser_execute(&parser, &settings, lpBuf, nBufLen);
				if(nParsed < 0) {
					//
				} else {
					param.http_major = parser.http_major;
					param.http_minor = parser.http_minor;
					param.status_code = parser.status_code;
					if(param.http_minor == 0) {
						m_ProxyType = PROXYTYPE_HTTP10;
					} else {
						m_ProxyType = PROXYTYPE_HTTP11;
					}
					switch (parser.method)
					{
					case http_method::HTTP_GET:
						param.method = PROXY_COMMAND::HTTP_GET;
						break;
					case http_method::HTTP_PUT:
						param.method = PROXY_COMMAND::HTTP_PUT;
						break;
					case http_method::HTTP_POST:
						param.method = PROXY_COMMAND::HTTP_POST;
						break;
					case http_method::HTTP_HEAD:
						param.method = PROXY_COMMAND::HTTP_HEAD;
						break;
					default:
						param.method = PROXY_COMMAND::HTTP_CONNECT;
						break;
					}
					if (parser.method != http_method::HTTP_CONNECT)
					{
						const char* url = param.at[ProxyParam::URL];
						int url_len = param.length[ProxyParam::URL];
						if (!strnicmp(url, "http://", 7))
						{
							//
						}
						else if (!strnicmp(url, "ftp://", 6))
						{
							switch (param.method)
							{
							case PROXY_COMMAND::HTTP_GET:
								param.method = PROXY_COMMAND::FTP_GET;
								break;
							case PROXY_COMMAND::HTTP_PUT:
								param.method = PROXY_COMMAND::FTP_PUT;
								break;
							default:
								break;
							}
						}
						else if (*url == '/')
						{
							param.transparent = 1;
						}
						else
						{
							OnProxyDone(513);
						}
					}
					else
					{
						//if ((se=strchr((char *)sb, ' ')) == NULL || sb==se) {OnProxyDone (514);}
						//*se = 0;
					}
					if (!param.transparent || parser.method != http_method::HTTP_CONNECT) {
					}
					if(param.at[ProxyParam::EXPECT]) {
						Base::SendBuf(proxy_stringtable[17], (int)strlen(proxy_stringtable[17]));
					} else {
						if(param.at[ProxyParam::CONTENT_LENGTH]) {
						// uint64_t length = std::atoll(param.at[ProxyParam::CONTENT_LENGTH]);
						// if(param->maxtrafout64 && (param->maxtrafout64 < param->statscli64 || length > param->maxtrafout64 - param->statscli64)){
						// 	OnProxyDone(10);
						// }
						} 
						if(IsProxyUserRequired()) {
							const char* user = param.at[ProxyParam::USERNAME];
							if(!user) {
								OnProxyDone(4);
							} else {
								const char* pwd = param.at[ProxyParam::PASSWORD];
								OnProxyAuth(user, param.length[ProxyParam::USERNAME], pwd, param.length[ProxyParam::PASSWORD]);
							}
						} else {
							char* host = (char*)param.at[ProxyParam::HOST];
							char* port = (char*)param.at[ProxyParam::PORT];
							if(host && port) {
								host[param.length[ProxyParam::HOST]] = 0;
								port[param.length[ProxyParam::PORT]] = 0;
								OnProxy(host, std::atoi(port));
							}
						}
					}
					return SOCKET_PACKET_FLAG_COMPLETE;
				}
			}
			break;
			}
		}
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  NMETHODS   	METHODS
				//1    1    		1 to 255
#if 1
				char hex[1024] = {0};
				int hexlen = 1024;
				HexEncode((const byte*)lpBuf, nBufLen, hex, &hexlen);
				PRINTF("%.*s\n", hexlen, hex);
#endif//
				switch (m_ProxyState) 
				{
				case 0:
					{
						if(nBufLen < 3) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						if (IsProxyAuthRequired()) {
							//需要使用用户名密码登录
							m_ProxyState = 2;
							Buf[0] = 0x05;
							Buf[1] = 0x02;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if (IsProxyUserRequired()) {
							//需要使用用户名登录
							m_ProxyState = 1;
							Buf[0] = 0x05;
							Buf[1] = 0xff;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else {
							//不需要使用用户名密码登录
							m_ProxyState = 1;
							Buf[0] = 0x05;
							Buf[1] = 0x00;
							Base::SendBuf(Buf, 2);
							return SOCKET_PACKET_FLAG_COMPLETE;
						}
					}
					break;
				case 1:
					{
						//VER  CMD  RSV  ATYP DST.ADDR    DST.PROT
						//1    1    1    1    Variable    2
						if(nBufLen < (4 + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						byte ATYP = lpBuf[3];
						if(ATYP == 0x01) { //IPV4
							if(nBufLen < (4 + 4 + 2)) {
								return SOCKET_PACKET_FLAG_PENDING;
							}
							u_long ip = *(u_long*)&lpBuf[4];
							u_short port = *(u_short*)&lpBuf[8];
							OnProxy(ip,port);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if(ATYP == 0X03) { //域名
							int addr_len = lpBuf[4];
							if(nBufLen < (4 + 1 + addr_len + 2)) {
								return SOCKET_PACKET_FLAG_PENDING;
							}
							char* addr = (char*)lpBuf + 4 + 1;
							u_short port = *(u_short*)&lpBuf[4 + addr_len];
							addr[addr_len] = 0;
							OnProxy(addr, port);
							return SOCKET_PACKET_FLAG_COMPLETE;
						} else if(ATYP == 0X03) { //IPV6
						}
					}
					break;
				case 2:
					{
						if(nBufLen < (1 + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						int user_len = lpBuf[1];
						if(nBufLen < (1 + 1 + user_len + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						const char* user = lpBuf + 1 + 1;
						int pwd_len = lpBuf[1 + 1 + user_len];
						//lpBuf[1 + 1 + user_len] = 0;
						if(nBufLen < (1 + 1 + user_len + 1 + pwd_len + 1)) {
							return SOCKET_PACKET_FLAG_PENDING;
						}
						const char* pwd = user + user_len + 1;
						//lpBuf[1 + 1 + user_len + 1 + pwd_len] = 0;
						OnProxyAuth(user, user_len, pwd, pwd_len);
						return SOCKET_PACKET_FLAG_COMPLETE;
					}
					break;
				default:
					break;
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				
			}
			break;
		}
		m_ProxyType = PROXYTYPE_NONE;
		m_ProxyState = PROXY_STATE_NONE;
		return 0;
	}

	virtual void OnProxyAuth(const char* user, int user_len, const char* pwd, int pwd_len)
	{

	}
	
	virtual void OnProxyAuthDone(int nErrorCode)
	{
		if(nErrorCode) {
			OnProxyDone(nErrorCode);
			return;
		}
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				ASSERT(0);
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  METHOD
				//1    1
				m_ProxyState = 1;
				Buf[0] = 0x05;
				Buf[1] = 0x00; //
				Base::SendBuf(Buf,2);
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				snprintf(Buf, 1024, "HTTP/1.0 200 OK\r\n"
					"Content-Type: text/html\r\n"
					"Connection: keep-alive\r\n"
					"Content-Length: %d\r\n\r\n", 0);
			}
			break;
		}
	}

	virtual void OnProxy(const char* addr, u_short prot)
	{
		ProxyAddr_.sin_family = AF_INET;
		ProxyAddr_.sin_port = prot;
		ProxyAddr_.sin_addr.s_addr = Ip2N(Url2Ip((char*)(addr)));
		OnProxy(ProxyAddr_);
	}

	inline void OnProxy(u_long ip, u_short port)
	{
		ProxyAddr_.sin_family = AF_INET;
		ProxyAddr_.sin_port = port;
		ProxyAddr_.sin_addr.s_addr = ip;
		OnProxy(ProxyAddr_);
	}

	virtual void OnProxy(const SOCKADDR_IN& addr)
	{
	}
	
	virtual void OnProxyDone(int nErrorCode)
	{
		char Buf[1024] = {0};
		switch(m_ProxyType)
		{
		case PROXYTYPE_SOCKS4:
		case PROXYTYPE_SOCKS4A:
			{
				//VN  	CD  	DSTPORT	DSTIP                
				//1		1		2		4
				Buf[0] = 0x00;
				if(nErrorCode) {
					Buf[1] = 0x5B;
				} else {
					m_ProxyState = PROXY_STATE_OK;
					Buf[1] = 0x5A;
				}
				memcpy(Buf + 2, &ProxyAddr_.sin_port, sizeof(ProxyAddr_.sin_port));
				memcpy(Buf + 2 + 2, &ProxyAddr_.sin_addr.s_addr, sizeof(ProxyAddr_.sin_addr.s_addr));
				Base::SendBuf(Buf,9);
			}
			break;
		case PROXYTYPE_SOCKS5:
			{
				//VER  REP  RSV   ATYP    DST.ADDR    DST.PROT
				//1    1    1     1       Variable    2
				if(!nErrorCode) {
					m_ProxyState = PROXY_STATE_OK;
					Buf[0] = 0x05; //VER
					Buf[1] = 0x00; //CD
					Buf[2] = 0x00; //RSV
					Buf[3] = 0x01; //ATYP
					//memcpy(Buf + 4, &ProxyAddr_.sin_addr.s_addr, sizeof(ProxyAddr_.sin_addr.s_addr));
					//memcpy(Buf + 4 + 4, &ProxyAddr_.sin_port, sizeof(ProxyAddr_.sin_port));
					Base::SendBuf(Buf,10);
				}
			}
			break;
		case PROXYTYPE_HTTP10:
		case PROXYTYPE_HTTP11:
			{
				if(nErrorCode != 555 && (nErrorCode < 90 || nErrorCode >=800 || nErrorCode == 100 ||(nErrorCode > 500 && nErrorCode< 800))) {
					//if((nErrorCode>=509 && nErrorCode < 517) || nErrorCode > 900) while( (i = sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, '\n')) > 2);
					if(nErrorCode == 10) {
						Base::SendBuf(proxy_stringtable[2], (int)strlen(proxy_stringtable[2]));
					}
					// else if (res == 700 || res == 701){
					// 	Base::SendBuf(proxy_stringtable[16], (int)strlen(proxy_stringtable[16]));
					// 	Base::SendBuf(ftpbuf, inftpbuf);
					// }
					else if(nErrorCode == 100 || (nErrorCode >10 && nErrorCode < 20) || (nErrorCode >701 && nErrorCode <= 705)) {
						Base::SendBuf(proxy_stringtable[1], (int)strlen(proxy_stringtable[1]));
					}
					else if(nErrorCode >=20 && nErrorCode < 30) {
						Base::SendBuf(proxy_stringtable[6], (int)strlen(proxy_stringtable[6]));
					}
					else if(nErrorCode >=30 && nErrorCode < 80) {
						Base::SendBuf(proxy_stringtable[5], (int)strlen(proxy_stringtable[5]));
					}
					else if(nErrorCode == 1 || (!IsProxyUserRequired() && nErrorCode < 10)) {
						Base::SendBuf(proxy_stringtable[11], (int)strlen(proxy_stringtable[11]));
					}
					else if(nErrorCode < 10) {
						if(IsProxyNTLMRequired()) {
							Base::SendBuf(proxy_stringtable[12], (int)strlen(proxy_stringtable[12]));
						} else {
							Base::SendBuf(proxy_stringtable[7], (int)strlen(proxy_stringtable[7]));
						}
					}
					else if(nErrorCode == 999) {
						Base::SendBuf(proxy_stringtable[4], (int)strlen(proxy_stringtable[4]));
					}
					else if(nErrorCode == 519) {
						Base::SendBuf(proxy_stringtable[3], (int)strlen(proxy_stringtable[3]));
					}
					else if(nErrorCode == 517) {
						Base::SendBuf(proxy_stringtable[15], (int)strlen(proxy_stringtable[15]));
					}
					else if(nErrorCode == 780) {
						Base::SendBuf(proxy_stringtable[10], (int)strlen(proxy_stringtable[10]));
					}
					else if(nErrorCode >= 511 && nErrorCode<=516){
						Base::SendBuf(proxy_stringtable[0], (int)strlen(proxy_stringtable[0]));
					}
				} 
			}
			break;
		}
	}

	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen) 
	{ 
		if(!IsProxyOK()) {
			return ReceiveProxy(lpBuf, nBufLen);
		}
		return Base::ParseBuf(lpBuf, nBufLen);
	}
};

}

#endif//_H_XHTTP_PROXY_IMPL_H_
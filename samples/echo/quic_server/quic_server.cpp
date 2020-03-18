// server.cpp : 定义控制台应用程序的入口点。
//

#include "../../samples.h"
#include "../../../XSocket/XSocketImpl.h"
#include "../../../XSocket/XQuickImpl.h"
#ifdef USE_EPOLL
#include "../../../XSocket/XEPoll.h"
#elif defined(USE_IOCP)
#include "../../../XSocket/XCompletionPort.h"
#endif//
#ifdef USE_OPENSSL
#include "../../../XSocket/XSSLImpl.h"
#endif
#include "../../../XSocket/XSimpleImpl.h"
using namespace XSocket;
#include <random>

#ifdef WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif//
{
	return 0;
}


# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# add location of platform.hpp for Windows builds
if(WIN32)
  #需要兼容XP时,定义_WIN32_WINNT 0x0501
  ADD_DEFINITIONS(-D_WIN32_WINNT=0x0602)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
  add_definitions(-DWIN32 -D_WINDOWS)
  # Same name on 64bit systems
  link_libraries(ws2_32.lib Mswsock.lib)
else()
  add_definitions(-g -W -Wall -fPIC)
endif()

FIND_PACKAGE(ZLIB REQUIRED)
IF(ZLIB_FOUND)
	MESSAGE(STATUS "zlib library status:")
	MESSAGE(STATUS "     version: ${ZLIB_VERSION}")
	MESSAGE(STATUS "     include path: ${ZLIB_INCLUDE_DIR}")
	MESSAGE(STATUS "     library path: ${ZLIB_LIBRARIES}")
	INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
  LINK_DIRECTORIES(${ZLIB_INCLUDE_DIR}/../${CMAKE_BUILD_TYPE}/lib)
	SET(EXTRA_LIBS ${EXTRA_LIBS} ${ZLIB_LIBRARIES})
ELSE()
	MESSAGE(FATAL_ERROR "zlib library not found")
ENDIF()

FIND_PACKAGE(OpenSSL REQUIRED)
IF(OpenSSL_FOUND)
	MESSAGE(STATUS "OpenSSL library status:")
	MESSAGE(STATUS "     version: ${OPENSSL_VERSION}")
	MESSAGE(STATUS "     include path: ${OPENSSL_INCLUDE_DIR}")
	MESSAGE(STATUS "     library path: ${OPENSSL_CRYPTO_LIBRARY}")
	MESSAGE(STATUS "     library path: ${OPENSSL_SSL_LIBRARY}")
	MESSAGE(STATUS "     library path: ${OPENSSL_LIBRARIES}")
	INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
  LINK_DIRECTORIES(${OPENSSL_INCLUDE_DIR}/../${CMAKE_BUILD_TYPE}/lib)
	SET(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_LIBRARIES})
ELSE()
	MESSAGE(FATAL_ERROR "OpenSSL library not found")
ENDIF()

#添加头文件搜索路径
INCLUDE_DIRECTORIES(../../../XSocket)
#添加库文件搜索路径
#LINK_DIRECTORIES(../../local/lib64)

IF(WIN32)
	SET (EXTRA_LIBS ${EXTRA_LIBS} XSocket)
ELSE()
	SET (EXTRA_LIBS ${EXTRA_LIBS} XSocket pthread)
ENDIF()

# 添加可执行文件
ADD_EXECUTABLE(http_client
    http_client.cpp
    ../../../XSocket/XCodec.cpp
    ../../../XSocket/XSocket.cpp
    ../../../XSocket/XSocketEx.cpp
    ../../../XSocket/XProxySocketEx.cpp
    ../../../XSocket/http-parser/http_parser.c
    #../../../XSocket/ws-parser/ws_parser.c
    ../../../XSocket/websocket-parser/websocket_parser.c
)
TARGET_LINK_LIBRARIES(http_client ${EXTRA_LIBS})
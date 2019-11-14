# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

ADD_DEFINITIONS(-std=c++11)

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

#添加头文件搜索路径
#INCLUDE_DIRECTORIES(../../../XSocket)
#添加库文件搜索路径
#LINK_DIRECTORIES(../../local/lib64)

IF(WIN32)
	SET (EXTRA_LIBS ${EXTRA_LIBS} XSocket)
ELSE()
	SET (EXTRA_LIBS ${EXTRA_LIBS} XSocket pthread)
ENDIF()

# 添加可执行文件
ADD_EXECUTABLE(client
    client.cpp
    ../../../XSocket/XSocket.cpp
    ../../../XSocket/XSocketEx.cpp
    ../../../XSocket/XProxySocketEx.cpp
)
TARGET_LINK_LIBRARIES(client ${EXTRA_LIBS})
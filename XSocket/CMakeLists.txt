# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

ADD_DEFINITIONS(-std=c++11)

if(WIN32)
  #需要兼容XP时,定义_WIN32_WINNT 0x0501
  ADD_DEFINITIONS(-D_WIN32_WINNT=0x0602)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
  add_definitions(-DWIN32 -D_WINDOWS -DWIN32_LEAN_AND_MEAN)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
  # Same name on 64bit systems
  link_libraries(ws2_32.lib Mswsock.lib)
else()
  add_definitions(-g -W -Wall -fPIC -fpermissive)
endif()

if(WIN32)
aux_source_directory(./src/win SRC_LIST)
else()
aux_source_directory(./src/linux SRC_LIST)
endif()
set(SRC_LIST ${SRC_LIST} 
./XSocket.cpp
./XSocketEx.cpp
./XProxySocketEx.cpp
)

add_library( # Sets the name of the library.
        XSocket

        # Sets the library as a shared library.
        STATIC

        # Provides a relative path to your source file(s).
        ${SRC_LIST}
        )
SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
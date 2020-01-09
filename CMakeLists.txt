# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.4.1)

# 项目名
project(xsocketx)

# 版本号.
set (PROJECT_VERSION_MAJOR 2)
set (PROJECT_VERSION_MINOR 9)
set (PROJECT_VERSION_PATCH 7)
 
# 系统
MESSAGE(STATUS "CMAKE_SYSTEM_NAME: " ${CMAKE_SYSTEM_NAME})

# 平台
IF(CMAKE_CL_64)
  SET(PLATFORM x64)
ELSE()
  SET(PLATFORM x86)
ENDIF()

MESSAGE(STATUS "PLATFORM: " ${PLATFORM})

add_subdirectory(XSocket)
add_subdirectory(samples)


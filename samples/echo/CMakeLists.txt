# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.4.1)

project(echo)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(http_client)
add_subdirectory(http_server)
add_subdirectory(quic_server)
#add_subdirectory(http3_server)


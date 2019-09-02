cmake_minimum_required(VERSION 3.14)
project(fuzzer)

set(CMAKE_CXX_STANDARD 14)
add_subdirectory(namespace)
add_subdirectory(kinterface)
add_executable(fuzzer main.cpp)
target_link_libraries(fuzzer namespace_static)
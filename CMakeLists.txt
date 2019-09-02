cmake_minimum_required(VERSION 3.10)
project(fuzzer)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)

add_subdirectory(namespace)
add_subdirectory(kinterface)
add_executable(fuzzer main.cpp)
target_link_libraries(fuzzer namespace_static)
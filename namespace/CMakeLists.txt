include_directories(${PROJECT_SOURCE_DIR}/include )

set(srcs namespace.cpp)

#set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
# 生成动态库目标
add_library(namespace_share SHARED ${srcs})
add_library(namespace_static STATIC ${srcs})

# 指定静态库的输出名称
set_target_properties(namespace_share PROPERTIES OUTPUT_NAME "namespace")
set_target_properties(namespace_static PROPERTIES OUTPUT_NAME "namespace")
# 使动态库和静态库同时存在
set_target_properties(namespace_share PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(namespace_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

set(test-srcs namespace_test.cpp)
add_executable(namespace_test ${test-srcs})
target_link_libraries(namespace_test namespace_static)
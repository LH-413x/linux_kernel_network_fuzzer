include_directories(${PROJECT_SOURCE_DIR}/namespace )
set(srcs_lib xfrm.cpp)

add_library(xfrm_nl_share SHARED ${srcs_lib})
add_library(xfrm_nl_static STATIC ${srcs_lib})

find_package(PkgConfig)
pkg_check_modules(NL3 REQUIRED
        libnl-3.0 libnl-genl-3.0
        libnl-route-3.0 libnl-xfrm-3.0)

include_directories(${NL3_INCLUDE_DIRS})
include_directories(
        ${PROJECT_SOURCE_DIR}/utils
)
link_directories(${CMAKE_BINARY_DIR}/Lib /usr/local/lib /home/clion/workspace)

#not need to use libnl now, but need to read source code
target_link_libraries(xfrm_nl_static ${NL3_LIBRARIES})
target_link_libraries(xfrm_nl_share ${NL3_LIBRARIES})

set_target_properties(xfrm_nl_share PROPERTIES OUTPUT_NAME "xfrm_nl")
set_target_properties(xfrm_nl_static PROPERTIES OUTPUT_NAME "xfrm_nl")

set_target_properties(xfrm_nl_share PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(xfrm_nl_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

set(test_srcs xfrm_nl_test.cpp)

add_executable(xfrm_nl_test ${test_srcs})

target_link_libraries(xfrm_nl_test xfrm_nl_static ${CMAKE_BINARY_DIR}/Lib/libnamespace.a)
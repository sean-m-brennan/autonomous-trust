cmake_minimum_required(VERSION 3.22)
project(autonomous_trust C)

set(CMAKE_C_STANDARD 11)

find_path(LIBUUID_INCLUDE_DIR uuid.h PATH_SUFFIXES uuid)
find_library(LIBUUID_LIBRARY libuuid.a)
include_directories(${LIBUUID_INCLUDE_DIR})

find_path(LIBB64_INCLUDE_DIR cencode.h PATH_SUFFIXES b64)
find_library(LIBB64_LIBRARY libb64.a)
include_directories(${LIBB64_INCLUDE_DIR})

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

find_path(LIBPROTOBUFC_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c)
find_library(LIBPROTOBUFC_LIBRARY libprotobuf-c.a)
include_directories(${LIBPROTOBUFC_INCLUDE_DIR})

set(DEPENDENCIES ${LIBUUID_LIBRARY} ${LIBB64_LIBRARY} ${LIBPROTOBUF_LIBRARY} ${LIBPROTOBUFC_LIBRARY})

add_compile_options(-Wall -Werror -fms-extensions)

set(PROTO_SOURCE_DIR "${CMAKE_SOURCE_DIR}/proto")
set(PROTO_BINARY_DIR "${CMAKE_SOURCE_DIR}/proto/generated")

set(proto_in
        agreement.proto
        datetime.proto
        identity.proto
        merkle.proto
        network.proto
        peers.proto
        processes.proto
)

set(proto_path "")
set(proto_src "")
set(proto_hdr "")
foreach(proto ${proto_in})
        set(proto_path ${proto_path} ${PROTO_SOURCE_DIR}/${proto})
        string(REGEX REPLACE "[.].proto$" ".pb-c.c" a_src ${proto})
        set(proto_src ${proto_src} "${PROTO_BINARY_DIR}/${a_src}")
        string(REGEX REPLACE "[.].proto$" ".pb-c.h" a_src ${proto})
        set(proto_hdr ${proto_hdr} "${PROTO_BINARY_DIR}/${a_src}")
endforeach()


set(libsrc
        autonomous_trust.c
        processes.c
        config/configuration.c
        identity/identity.c
	#network/network.c
        structures/array.c
        structures/datetime.c
	structures/map.c
        structures/merkle.c
        structures/misc.c
        structures/redblack.c
        utilities/message.c
        utilities/logger.c
        utilities/util.c
)

set(allhdr
        processes.h
        config/configuration.h
        identity/identity.h
	#network/network.h
        structures/array.h
        structes/datetime.h
	structures/map.h
        structures/merkle.h
        structures/redblack.h
	structures/structures.h
        utilities/logger.h
        utilities/util.h
)

set(PROTOC_C_EXECUTABLE protoc-c)
add_custom_target(protoc-c-generated-files
       COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_BINARY_DIR}
       COMMAND ${PROTOC_C_EXECUTABLE} --c_out ${PROTO_BINARY_DIR} -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${proto_in}
       COMMENT "Running C protocol buffer compiler on ${proto_in}"
       BYPRODUCTS ${proto_src} ${proto_hdr}
       SOURCES ${proto_path}
)
include_directories(${PROTO_BINARY_DIR})

add_library(autonomous_trust SHARED ${libsrc} ${proto_src})

add_library(autonomous_trust_static STATIC ${libsrc} ${proto_src})
set_target_properties(autonomous_trust_static PROPERTIES OUTPUT_NAME autonomous_trust)


add_executable(rb_test test/rb_test.c)
target_link_libraries(rb_test PRIVATE autonomous_trust_static ${DEPENDENCIES})
add_executable(array_test test/array_test.c)
target_link_libraries(array_test PRIVATE autonomous_trust_static ${DEPENDENCIES})
add_executable(logger_test test/logging_test.c)
target_link_libraries(logger_test PRIVATE autonomous_trust_static ${DEPENDENCIES})

# enable testing functionality
enable_testing()

# define tests
add_test(NAME rb_test COMMAND $<TARGET_FILE:rb_test>)
add_test(NAME array_test COMMAND $<TARGET_FILE:array_test>)
add_test(NAME logger_test COMMAND $<TARGET_FILE:logger_test>)

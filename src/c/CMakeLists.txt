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

find_path(LIBPROTOBUF_C_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c)
find_library(LIBPROTOBUF_C_LIBRARY libprotobuf-c.a)
include_directories(${LIBPROTOBUF_C_INCLUDE_DIR})
find_program(PROTOC_C_EXE protoc-c)

set(DEPENDENCIES
        ${LIBUUID_LIBRARY}
        ${LIBB64_LIBRARY}
        ${LIBPROTOBUF_LIBRARY}
        ${LIBPROTOBUF_C_LIBRARY}
)

add_compile_options(-Wall -Werror -fms-extensions)

set(PROTO_SOURCE_DIR "${CMAKE_SOURCE_DIR}/proto")
set(PROTO_BINARY_DIR "${CMAKE_SOURCE_DIR}/proto/c")

set(protos
        autonomous_trust/protobuf/agreement.proto
        autonomous_trust/protobuf/identity.proto
        autonomous_trust/protobuf/network.proto
        autonomous_trust/protobuf/peers.proto
        autonomous_trust/protobuf/processes.proto
        autonomous_trust/protobuf/structures/datetime.proto
        autonomous_trust/protobuf/structures/merkle.proto
)

set(google_protos
        google/protobuf/duration.proto
        google/protobuf/descriptor.proto
        google/protobuf/any.proto
        google/protobuf/timestamp.proto
        google/protobuf/source_context.proto
        google/protobuf/field_mask.proto
        google/protobuf/api.proto
        google/protobuf/struct.proto
        google/protobuf/empty.proto
        google/protobuf/type.proto
        google/protobuf/wrappers.proto
)

set(libsrc
        autonomous_trust/autonomous_trust.c
        autonomous_trust/config/configuration.c
        autonomous_trust/config/processes.c
        autonomous_trust/identity/identity.c
	#autonomous_trust/network/network.c
        autonomous_trust/structures/array.c
        autonomous_trust/structures/datetime.c
        autonomous_trust/structures/map.c
        autonomous_trust/structures/merkle.c
        autonomous_trust/structures/misc.c
        autonomous_trust/structures/redblack.c
        autonomous_trust/utilities/message.c
        autonomous_trust/utilities/logger.c
        autonomous_trust/utilities/util.c
)
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/autonomous_trust)


function(protoc_c_gen _proto _full_proto _dir)
        get_filename_component(_base ${_proto} NAME_WE)
        set(_pb_c_src ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb-c.c)
        add_custom_command(
                OUTPUT ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb-c.h ${_pb_c_src}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_BINARY_DIR}/${_dir}
                COMMAND ${PROTOC_C_EXE} --c_out ${PROTO_BINARY_DIR} -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${_full_proto}
                COMMENT "Building C protocol buffer C sources from ${_proto}"
                DEPENDS ${_full_proto} ${LIBPROTOBUF_C_LIBRARY} ${LIBPROTOBUF_LIBRARY} ${PROTOC_C_EXE}
                VERBATIM
        )
        set(proto_c_src ${proto_c_src} ${_pb_c_src} PARENT_SCOPE)
endfunction()

foreach(_proto ${protos})
        get_filename_component(_dir ${_proto} DIRECTORY)
        set(_fullproto ${PROTO_SOURCE_DIR}/${_proto})
        protoc_c_gen(${_proto} ${_fullproto} ${_dir})
endforeach()

foreach(_proto ${google_protos})
        # assumes relative path (google/protobuf/smthg.proto)
        get_filename_component(_dir ${_proto} DIRECTORY)
        set(_fullproto ${Protobuf_INCLUDE_DIRS}/${_proto})
        protoc_c_gen(${_proto} ${_fullproto} ${_dir})
endforeach()

include_directories(${PROTO_BINARY_DIR} ${PROTO_BINARY_DIR}/autonomous_trust/protobuf)


add_library(autonomous_trust SHARED ${libsrc} ${proto_c_src})

add_library(autonomous_trust_static STATIC ${libsrc} ${proto_c_src})
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

cmake_minimum_required(VERSION 3.22)
project(autonomous_trust C)

set(CMAKE_C_STANDARD 11)


####################
# library/program dependencies

find_path(LIBUUID_INCLUDE_DIR uuid.h PATH_SUFFIXES uuid)
find_library(LIBUUID_LIBRARY libuuid.so)
include_directories(${LIBUUID_INCLUDE_DIR})

find_path(LIBSODIUM_INCLUDE_DIR sodium.h)
find_library(LIBSODIUM_LIBRARY libsodium.so)
include_directories(${LIBSODIUM_INCLUDE_DIR})

find_path(LIBJANSSON_INCLUDE_DIR jansson.h)
find_library(LIBJANSSON_LIBRARY libjansson.so)
include_directories(${LIBJANSSON_INCLUDE_DIR})

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
find_program(PROTOC_COMPILER protoc)

find_path(LIBPROTOBUF_C_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c)
find_library(LIBPROTOBUF_C_LIBRARY libprotobuf-c.so)
include_directories(${LIBPROTOBUF_C_INCLUDE_DIR})
find_program(PROTOC_C_EXE protoc-c)

find_path(LIBPTHREAD_INCLUDE_DIR pthread.h)
include_directories(${LIBPTHREAD_INCLUDE_DIR})


set(DEPENDENCIES
        ${LIBUUID_LIBRARY}
        ${LIBSODIUM_LIBRARY}
        ${LIBPROTOBUF_LIBRARY}
        ${LIBPROTOBUF_C_LIBRARY}
        ${LIBJANSSON_LIBRARY}
)


####################
# sources

set(top_src_dir ${CMAKE_SOURCE_DIR}/../..)

set(linker_script ${CMAKE_SOURCE_DIR}/section_link.lds)
add_compile_options(-Wall -Werror -fms-extensions)
add_link_options(-pthread)

set(PROTO_SOURCE_DIR "${CMAKE_SOURCE_DIR}/proto")
set(PROTO_BINARY_DIR "${CMAKE_SOURCE_DIR}/proto/c")

set(protos
        autonomous_trust/core/protobuf/agreement.proto
        autonomous_trust/core/protobuf/capabilities.proto
        autonomous_trust/core/protobuf/identity.proto
        autonomous_trust/core/protobuf/network.proto
        autonomous_trust/core/protobuf/peers.proto
        autonomous_trust/core/protobuf/processes.proto
        autonomous_trust/core/protobuf/structures/datetime.proto
        autonomous_trust/core/protobuf/structures/merkle.proto
)

set(google_protos
        google/protobuf/any.proto
)

set(table_headers_in
        autonomous_trust/config/config_table.h.in
        autonomous_trust/processes/process_table.h.in
)

set(libsrc
        autonomous_trust/autonomous_trust.c
        autonomous_trust/config/configuration.c
        autonomous_trust/config/serialization.c
        autonomous_trust/config/sighandler.c
        autonomous_trust/identity/identity.c
        autonomous_trust/identity/id_proc.c
	autonomous_trust/network/network.c
	autonomous_trust/network/net_proc.c
        autonomous_trust/processes/process_tracker.c
        autonomous_trust/processes/processes.c
        autonomous_trust/structures/array.c
        autonomous_trust/structures/data.c
        autonomous_trust/structures/datetime.c
        autonomous_trust/structures/map.c
        autonomous_trust/structures/merkle.c
        autonomous_trust/structures/redblack.c
        autonomous_trust/utilities/message.c
        autonomous_trust/utilities/logger.c
        autonomous_trust/utilities/util.c
)
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/autonomous_trust)

####################
# get latest version

find_package(Git)
if (GIT_FOUND AND EXISTS "${top_src_dir}/.git")
        #include(GetGitRevisionDescription)
        execute_process(COMMAND ${GIT_EXECUTABLE} describe HEAD OUTPUT_VARIABLE TAG OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX REPLACE "^v" "" VERSION ${TAG})
        set(REVISION ${VERSION} CACHE STRING "git tag" FORCE)
else()
    message(WARNING "Git not found, cannot set version info")
    SET(REVISION "unknown")
endif()

include_directories(${CMAKE_BINARY_DIR})
configure_file("${CMAKE_SOURCE_DIR}/autonomous_trust/version.h.in" "${CMAKE_BINARY_DIR}/version.h" @ONLY)

####################
# generate tables headers

function(preprocess _file_in)
        get_filename_component(_base ${_file_in} NAME_WE)
        set(_fullpath ${CMAKE_SOURCE_DIR}/${_file_in})
        set(_header_file ${CMAKE_BINARY_DIR}/${_base}.h)
        set(_src_dir ${CMAKE_SOURCE_DIR})
        add_custom_command(
                OUTPUT ${_header_file}
                COMMAND python ${CMAKE_SOURCE_DIR}/preprocess.py ${_fullpath} ${_header_file} ${_src_dir}/ autonomous_trust
                COMMENT "Preprocessing table header from ${_file_in}"
                DEPENDS ${_fullpath}
        )
        set(table_hdrs ${table_hdrs} ${_header_file} PARENT_SCOPE)
endfunction()

foreach(_hdr ${table_headers_in})
        preprocess(${_hdr})
endforeach()

####################
# compile proto files

## generate a C source
function(protoc_c_gen _proto _full_proto _dir)
        get_filename_component(_base ${_proto} NAME_WE)
        set(_pb_c_src ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb-c.c)
        add_custom_command(
                OUTPUT ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb-c.h ${_pb_c_src}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_BINARY_DIR}
                COMMAND ${PROTOC_C_EXE} --c_out ${PROTO_BINARY_DIR} -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${_full_proto}
                COMMENT "Building protocol buffer C sources from ${_proto}"
                DEPENDS ${_full_proto} ${LIBPROTOBUF_C_LIBRARY} ${LIBPROTOBUF_LIBRARY} ${PROTOC_C_EXE}
                VERBATIM
        )
        set(proto_c_src ${proto_c_src} ${_pb_c_src} PARENT_SCOPE)
endfunction()

## generate a Python source
function(protoc_py_gen _proto _full_proto _dir)
        get_filename_component(_base ${_proto} NAME_WE)
        set(_pb_py_src ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb2.py)
        add_custom_command(
                OUTPUT ${_pb_py_src}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_SOURCE_DIR}/py
                # FIXME discover protoc path
                COMMAND protoc --python_out=${PROTO_SOURCE_DIR}/py -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${_full_proto}
                COMMAND ${CMAKE_COMMAND} -E touch ${PROTO_SOURCE_DIR}/py/${_dir}/init.py
                COMMENT "Building protocol buffer Python sources from ${_proto}"
                DEPENDS ${_full_proto} ${LIBPROTOBUF_LIBRARY}
                VERBATIM
        )
        set(proto_py_src ${proto_py_src} ${_pb_py_src} PARENT_SCOPE)
endfunction()

## apply generators to proto files
foreach(_proto ${protos})
        get_filename_component(_dir ${_proto} DIRECTORY)
        set(_fullproto ${PROTO_SOURCE_DIR}/${_proto})
        protoc_c_gen(${_proto} ${_fullproto} ${_dir})
        protoc_py_gen(${_proto} ${_fullproto} ${_dir})
        set(proto_rel ${proto_rel} proto/${_proto})
endforeach()

## apply C generator to Google proto files
foreach(_proto ${google_protos})
        # assumes relative path (google/protobuf/smthg.proto)
        get_filename_component(_dir ${_proto} DIRECTORY)
        set(_fullproto ${Protobuf_INCLUDE_DIRS}/${_proto})
        protoc_c_gen(${_proto} ${_fullproto} ${_dir})
endforeach()

include_directories(${PROTO_BINARY_DIR} ${PROTO_BINARY_DIR}/autonomous_trust/core)

## Python will not be built without specifying this target
add_custom_target(proto_python DEPENDS ${proto_py_src})


####################
# create libraries

add_library(autonomous_trust SHARED ${libsrc} ${proto_c_src} ${table_hdrs})

add_library(autonomous_trust_static STATIC ${libsrc} ${proto_c_src} ${table_hdrs})
set_target_properties(autonomous_trust_static PROPERTIES OUTPUT_NAME autonomous_trust)


####################
# example app

add_executable(at_example example.c)
target_link_libraries(at_example PRIVATE autonomous_trust_static ${DEPENDENCIES})
#target_link_libraries(at_example PRIVATE autonomous_trust ${DEPENDENCIES})


####################
# tests

add_executable(rb_test test/rb_test.c)
target_link_libraries(rb_test PRIVATE autonomous_trust_static ${DEPENDENCIES})
add_executable(array_test test/array_test.c)
target_link_libraries(array_test PRIVATE autonomous_trust_static ${DEPENDENCIES})
add_executable(logger_test test/logging_test.c)
target_link_libraries(logger_test PRIVATE autonomous_trust_static ${DEPENDENCIES})

enable_testing()

add_test(NAME rb_test COMMAND $<TARGET_FILE:rb_test>)
add_test(NAME array_test COMMAND $<TARGET_FILE:array_test>)
add_test(NAME logger_test COMMAND $<TARGET_FILE:logger_test>)

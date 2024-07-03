cmake_minimum_required(VERSION 3.23)

if(DEFINED ENV{CONDA_PREFIX})
    set(CONDA_ROOT $ENV{CONDA_PREFIX} CACHE PATH "Conda base directory")
    set(CMAKE_C_COMPILE_OPTIONS_SYSROOT "--sysroot=")
    set(CMAKE_CXX_COMPILE_OPTIONS_SYSROOT "--sysroot=")
    set(CONDA_SYSROOT ${CONDA_ROOT}/x86_64-conda-linux-gnu/sysroot)
    set(CMAKE_PREFIX_PATH ${CONDA_SYSROOT})
    #set(CMAKE_SYSROOT ${CONDA_SYSROOT})  # Doesn't work
    set(sysroot_flag --sysroot=${CONDA_SYSROOT})
    message("-- Conda is active; sysroot now at ${CONDA_SYSROOT}")
endif()

project(autonomous_trust C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

set(warning_as_error -Werror)
set(useful_warnings
    -Wshadow 
    -Wpointer-arith 
    -Wcast-align 
    -Wfloat-equal 
    #-Wextra
    -Wwrite-strings
    -Wswitch-enum
    -Winit-self
    -Wuse-after-free 
    -Wfree-nonheap-object
)
set(useful_flags
    #-fanalyzer
    -fstack-clash-protection
    -fstack-protector
)
string(REPLACE ";" " " lib_compile_flags
        "-Wall ${warning_as_error} ${useful_warnings} -fms-extensions ${useful_flags} ${sysroot_flag}")
add_compile_options(-Wall -fms-extensions)
add_link_options(-pthread ${sysroot_flag})


####################
# library/program dependencies

# UUID
find_path(LIBUUID_INCLUDE_DIR uuid.h PATH_SUFFIXES uuid PATHS ${CONDA_ROOT})
find_library(LIBUUID_LIBRARY libuuid.so PATHS ${CONDA_ROOT})
include_directories(${LIBUUID_INCLUDE_DIR})
if(LIBUUID_LIBRARY)
    message("-- Found libuuid at ${LIBUUID_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libuuid not found.")
endif()

# libsodium
find_path(LIBSODIUM_INCLUDE_DIR sodium.h PATHS ${CONDA_ROOT})
find_library(LIBSODIUM_LIBRARY libsodium.so PATHS ${CONDA_ROOT})
include_directories(${LIBSODIUM_INCLUDE_DIR})
if(LIBSODIUM_LIBRARY)
    message("-- Found libsodium at ${LIBSODIUM_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libsodium not found.")
endif()

# jansson
find_path(LIBJANSSON_INCLUDE_DIR jansson.h PATHS ${CONDA_ROOT})
find_library(LIBJANSSON_LIBRARY libjansson.so PATHS ${CONDA_ROOT})
include_directories(${LIBJANSSON_INCLUDE_DIR})
if(LIBJANSSON_LIBRARY)
    message("-- Found libjansson at ${LIBJANSSON_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libjansson not found.")
endif()

# protobuf
find_package(Protobuf REQUIRED)  # paths doesn't work
#find_path(Protobuf_INCLUDE_DIRS message.h PATH_SUFFIXES google/protobuf PATHS ${CONDA_ROOT})
#find_library(Protobuf_LIBRARY libprotobuf.so PATHS ${CONDA_ROOT})
include_directories(${Protobuf_INCLUDE_DIRS})
#find_program(Protobuf_PROTOC_EXECUTABLE protoc PATHS ${CONDA_ROOT})
#string(REPLACE "/google/protobuf" "" PROTOBUF_INCLUDE_DIR ${Protobuf_INCLUDE_DIRS})
#include_directories(${PROTOBUF_INCLUDE_DIR})
if(Protobuf_LIBRARY)
    message("-- Found libprotobuf at ${Protobuf_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libprotobuf not found.")
endif()

# protobuf-c
find_path(LIBPROTOBUF_C_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c PATHS ${CONDA_ROOT})
find_library(LIBPROTOBUF_C_LIBRARY libprotobuf-c.so PATHS ${CONDA_ROOT})
include_directories(${LIBPROTOBUF_C_INCLUDE_DIR})
find_program(PROTOC_C_EXE protoc-c PATHS ${CONDA_ROOT})
if(LIBPROTOBUF_C_LIBRARY)
    message("-- Found libprotobuf-c at ${LIBPROTOBUF_C_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libprotobuf-c not found.")
endif()

# check (testing only)
find_path(LIBCHECK_INCLUDE_DIR check.h PATHS ${CONDA_ROOT})
find_library(LIBCHECK_LIBRARY libcheck.so PATHS ${CONDA_ROOT})
include_directories(${LIBCHECK_INCLUDE_DIRS})
if(LIBCHECK_LIBRARY)
    message("-- Found libcheck at ${LIBCHECK_LIBRARY}")
else()
    message(ERROR "Testing dependency libcheck not found.")
endif()

set(DEPENDENCIES
    ${LIBUUID_LIBRARY}
    ${LIBSODIUM_LIBRARY}
    ${Protobuf_LIBRARY}
    ${LIBPROTOBUF_LIBRARY}
    ${LIBPROTOBUF_C_LIBRARY}
    ${LIBJANSSON_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
)

set(TEST_DEPENDENCIES
    ${DEPENDENCIES}
    ${LIBCHECK_LIBRARY}
)


####################
# sources

set(top_src_dir ${CMAKE_CURRENT_SOURCE_DIR}/../..)

set(PROTO_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/protobuf")

set(protos
    autonomous_trust/core/algorithms/agreement.proto
    autonomous_trust/core/identity/history.proto
    autonomous_trust/core/identity/identity.proto
    autonomous_trust/core/identity/protocol.proto
    autonomous_trust/core/negotiation/task.proto
    autonomous_trust/core/processes/capabilities.proto
    autonomous_trust/core/structures/dag.proto
    autonomous_trust/core/structures/data.proto
    autonomous_trust/core/structures/datetime.proto
    autonomous_trust/core/structures/map.proto
    autonomous_trust/core/structures/merkle.proto
)

set(google_protos
    google/protobuf/any.proto
)

set(table_headers_in
    autonomous_trust/config/config_table_priv.h.in
    autonomous_trust/processes/process_table_priv.h.in
    autonomous_trust/processes/capability_table_priv.h.in
    autonomous_trust/utilities/error_table_priv.h.in
)

set(libsrc
    autonomous_trust/autonomous_trust.c
    autonomous_trust/config/configuration.c
    autonomous_trust/config/protobuf_shutdown.cpp
    autonomous_trust/config/sighandler.c
    autonomous_trust/identity/encryptor.c
    autonomous_trust/identity/group.c
    autonomous_trust/identity/hexlify.c
    autonomous_trust/identity/identity.c
    autonomous_trust/identity/id_proc.c
    autonomous_trust/identity/signature.c
    autonomous_trust/negotiation/task.c
    autonomous_trust/network/net_proc.c
    autonomous_trust/network/network.c
    autonomous_trust/processes/capabilities.c
    autonomous_trust/processes/process_tracker.c
    autonomous_trust/processes/processes.c
    autonomous_trust/structures/array.c
    autonomous_trust/structures/data.c
    autonomous_trust/structures/datetime.c
    autonomous_trust/structures/map.c
    autonomous_trust/structures/merkle.c
    autonomous_trust/structures/redblack.c
    autonomous_trust/utilities/exception.c
    autonomous_trust/utilities/logger.c
    autonomous_trust/utilities/message.c
    autonomous_trust/utilities/msg_types.c
    autonomous_trust/utilities/util.c
)
set(libhdr
    autonomous_trust.h
    autonomous_trust/config/configuration.h
    autonomous_trust/config/sighandler.h
    autonomous_trust/identity/identity.h
    autonomous_trust/processes/capabilities.h
    autonomous_trust/structures/array.h
    autonomous_trust/structures/data.h
    autonomous_trust/structures/datetime.h
    autonomous_trust/structures/map.h
    autonomous_trust/utilities/exception.h
    autonomous_trust/utilities/logger.h
    autonomous_trust/utilities/message.h
    autonomous_trust/utilities/msg_types.h
)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust)

####################
# get latest version

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust/version.h)
    find_package(Git)
    if (GIT_FOUND AND EXISTS "${top_src_dir}/.git")
        execute_process(COMMAND ${GIT_EXECUTABLE} describe HEAD OUTPUT_VARIABLE TAG OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX REPLACE "^v" "" VERSION ${TAG})
        set(REVISION ${VERSION} CACHE STRING "git tag" FORCE)
    else()
        message(WARNING "Git not found, cannot set version info")
        SET(REVISION "unknown")
    endif()
endif()  

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/autonomous_trust)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust/version.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autonomous_trust/version.h" @ONLY)
set(genhdr ${CMAKE_CURRENT_BINARY_DIR}/autonomous_trust/version.h)
foreach(_hdr ${libhdr})
    configure_file(${_hdr} ${CMAKE_CURRENT_BINARY_DIR}/${_hdr} COPYONLY)
    set(genhdr ${genhdr} ${CMAKE_CURRENT_BINARY_DIR}/${_hdr})
endforeach()


####################
# generate tables headers

function(preprocess _file_in)
    get_filename_component(_base ${_file_in} NAME_WE)
    set(_fullpath ${CMAKE_CURRENT_SOURCE_DIR}/${_file_in})
    set(_header_file ${CMAKE_CURRENT_BINARY_DIR}/${_base}.h)
    set(_src_dir ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_command(
        OUTPUT ${_header_file}
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/preprocess.py ${_fullpath} ${_header_file} ${_src_dir}/ autonomous_trust
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
        COMMAND ${Protobuf_PROTOC_EXECUTABLE} --c_out ${PROTO_BINARY_DIR} -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${_full_proto}
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
    set(_fullproto ${PROTOBUF_INCLUDE_DIR}/${_proto})
    protoc_c_gen(${_proto} ${_fullproto} ${_dir})
endforeach()

include_directories(${PROTO_BINARY_DIR} ${PROTO_BINARY_DIR}/autonomous_trust/core)

## Python will not be built without specifying this target
add_custom_target(proto_python DEPENDS ${proto_py_src})


####################
# create libraries

add_library(autonomous_trust SHARED ${libsrc} ${libhdr} ${proto_c_src} ${table_hdrs})
set_target_properties(autonomous_trust PROPERTIES COMPILE_FLAGS "${lib_compile_flags}")
target_sources(autonomous_trust PUBLIC ${libsrc}
    PUBLIC FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR} FILES ${genhdr}
    )

add_library(autonomous_trust_static STATIC ${libsrc} ${libhdr} ${proto_c_src} ${table_hdrs})
set_target_properties(autonomous_trust_static PROPERTIES
    OUTPUT_NAME autonomous_trust
    COMPILE_FLAGS "${lib_compile_flags}"
    )
target_sources(autonomous_trust PUBLIC ${libsrc}
    PUBLIC FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR} FILES ${genhdr}
    )


####################
# example app

add_executable(at_example example.c)
target_link_libraries(at_example PRIVATE autonomous_trust_static ${DEPENDENCIES})
#target_link_libraries(at_example PRIVATE autonomous_trust ${DEPENDENCIES})
target_compile_options(at_example PRIVATE -Wall ${sysroot_flag})
target_link_options(at_example PRIVATE ${sysroot_flag})
target_link_directories(at_example PRIVATE ${CMAKE_SYSROOT})


####################
# tests

add_executable(rb_test test/rb_test.c)
set_source_files_properties(test/rb_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(rb_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_executable(exception_test test/exception_test.c)
set_source_files_properties(test/exception_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(exception_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_executable(array_test test/array_test.c)
set_source_files_properties(test/array_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(array_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_executable(map_test test/map_test.c)
set_source_files_properties(test/map_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(map_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_executable(logger_test test/logging_test.c)
set_source_files_properties(test/logging_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(logger_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_executable(proc_track_test test/proc_track_test.c)
set_source_files_properties(test/proc_track_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(proc_track_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

enable_testing()

add_test(NAME rb_test COMMAND $<TARGET_FILE:rb_test>)
add_test(NAME exception_test COMMAND $<TARGET_FILE:exception_test>)
add_test(NAME array_test COMMAND $<TARGET_FILE:array_test>)
add_test(NAME map_test COMMAND $<TARGET_FILE:map_test>)
add_test(NAME logger_test COMMAND $<TARGET_FILE:logger_test>)
add_test(NAME proc_track_test COMMAND $<TARGET_FILE:proc_track_test>)


####################
# Packaging

install(TARGETS autonomous_trust 
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        FILE_SET HEADERS
        )
install(TARGETS autonomous_trust_static
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        FILE_SET HEADERS
        )

include(CPack)

# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
cmake_minimum_required(VERSION 3.23)

if(DEFINED ENV{CONDA_PREFIX})
    set(CONDA_ROOT $ENV{CONDA_PREFIX} CACHE PATH "Conda base directory")
    set(CMAKE_C_COMPILE_OPTIONS_SYSROOT "--sysroot=")
    set(CMAKE_CXX_COMPILE_OPTIONS_SYSROOT "--sysroot=")
    set(CONDA_SYSROOT ${CONDA_ROOT}/x86_64-conda-linux-gnu/sysroot)
    # Put conda's env root FIRST in CMAKE_PREFIX_PATH so find_library picks
    # conda's libuuid/libsodium/libjansson before the system versions in
    # /usr/lib/x86_64-linux-gnu — otherwise RPATH points at conda but we
    # linked against system, creating a load-time mismatch risk.
    list(PREPEND CMAKE_PREFIX_PATH ${CONDA_ROOT} ${CONDA_SYSROOT})
    #set(CMAKE_SYSROOT ${CONDA_SYSROOT})  # Doesn't work
    set(sysroot_flag --sysroot=${CONDA_SYSROOT})
    # Ensure conda libs are found at runtime even without conda activated.
    # Append link-time dirs so conda RPATH is preferred over system paths,
    # and emit new-style DT_RUNPATH so LD_LIBRARY_PATH is still respected.
    set(CMAKE_INSTALL_RPATH "${CONDA_ROOT}/lib")
    set(CMAKE_BUILD_RPATH "${CONDA_ROOT}/lib")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    message("-- Conda is active; sysroot now at ${CONDA_SYSROOT}")
endif()

project(autonomous_trust C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

set(warning_as_error -Werror)
set(useful_warnings
    -Wshadow 
    -Wpointer-arith 
    -Wcast-align 
    -Wfloat-equal 
    -Wextra
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wwrite-strings
    -Wswitch-enum
    -Winit-self
)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND useful_warnings -Wuse-after-free -Wfree-nonheap-object -Wno-cast-function-type)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND useful_warnings -Wno-microsoft-anon-tag -Wno-deprecated-non-prototype -Wno-unused-but-set-variable -Wno-unknown-pragmas -Wno-cast-align -Wno-cast-function-type-mismatch)
endif()
set(useful_flags
    #-fanalyzer
    -fstack-protector
)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND useful_flags -fstack-clash-protection)
endif()
string(REPLACE ";" " " lib_compile_flags
        "-Wall ${warning_as_error} ${useful_warnings} -fms-extensions ${useful_flags} ${sysroot_flag}")
add_compile_options(-Wall -fms-extensions ${useful_warnings} ${warning_as_error} ${useful_flags})
add_link_options(-pthread ${sysroot_flag})

# Static linking option for embedded/IoT builds
option(AT_STATIC "Link at_demo fully statically (no shared library dependencies)" OFF)

# Zero Trust Architecture integration (requires OpenSSL)
option(AT_ZTA "Enable Zero Trust Architecture credential integration" OFF)

if(AT_STATIC)
    # Prefer .a archives in subsequent find_library() calls AND pass -static to
    # the linker so transitive deps resolve statically too. Must come BEFORE the
    # find_package()/find_library() calls below for the suffix override to take
    # effect. find_package(Protobuf) uses its own lookup logic that may still
    # return the .so if no .a is available — verify with `ldd <binary>` after
    # building; an AT_STATIC build should produce "not a dynamic executable".
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()


####################
# library/program dependencies

# UUID
find_path(LIBUUID_INCLUDE_DIR uuid.h PATH_SUFFIXES uuid HINTS ${CONDA_ROOT})
find_library(LIBUUID_LIBRARY NAMES uuid HINTS ${CONDA_ROOT})
include_directories(${LIBUUID_INCLUDE_DIR})
if(LIBUUID_LIBRARY)
    message("-- Found libuuid at ${LIBUUID_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libuuid not found.")
endif()

# libsodium
find_path(LIBSODIUM_INCLUDE_DIR sodium.h HINTS ${CONDA_ROOT})
find_library(LIBSODIUM_LIBRARY NAMES sodium HINTS ${CONDA_ROOT})
include_directories(${LIBSODIUM_INCLUDE_DIR})
if(LIBSODIUM_LIBRARY)
    message("-- Found libsodium at ${LIBSODIUM_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libsodium not found.")
endif()

# jansson
find_path(LIBJANSSON_INCLUDE_DIR jansson.h HINTS ${CONDA_ROOT})
find_library(LIBJANSSON_LIBRARY NAMES jansson HINTS ${CONDA_ROOT})
include_directories(${LIBJANSSON_INCLUDE_DIR})
if(LIBJANSSON_LIBRARY)
    message("-- Found libjansson at ${LIBJANSSON_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libjansson not found.")
endif()

# protobuf
find_package(Protobuf REQUIRED)  # paths doesn't work
#find_path(Protobuf_INCLUDE_DIRS message.h PATH_SUFFIXES google/protobuf HINTS ${CONDA_ROOT})
#find_library(Protobuf_LIBRARY libprotobuf.so HINTS ${CONDA_ROOT})
include_directories(${Protobuf_INCLUDE_DIRS})
#find_program(Protobuf_PROTOC_EXECUTABLE protoc HINTS ${CONDA_ROOT})
#string(REPLACE "/google/protobuf" "" PROTOBUF_INCLUDE_DIR ${Protobuf_INCLUDE_DIRS})
#include_directories(${PROTOBUF_INCLUDE_DIR})
if(Protobuf_LIBRARY)
    message("-- Found libprotobuf at ${Protobuf_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libprotobuf not found.")
endif()

# protobuf-c
find_path(LIBPROTOBUF_C_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c HINTS ${CONDA_ROOT})
find_library(LIBPROTOBUF_C_LIBRARY NAMES protobuf-c HINTS ${CONDA_ROOT})
include_directories(${LIBPROTOBUF_C_INCLUDE_DIR})
#find_program(PROTOC_C_EXE protoc-c HINTS ${CONDA_ROOT})
if(LIBPROTOBUF_C_LIBRARY)
    message("-- Found libprotobuf-c at ${LIBPROTOBUF_C_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libprotobuf-c not found.")
endif()

# check (testing only — optional for non-test builds)
find_path(LIBCHECK_INCLUDE_DIR check.h HINTS ${CONDA_ROOT})
find_library(LIBCHECK_LIBRARY NAMES check libcheck.so libcheck.a HINTS ${CONDA_ROOT})
if(LIBCHECK_LIBRARY)
    include_directories(${LIBCHECK_INCLUDE_DIR})
    message("-- Found libcheck at ${LIBCHECK_LIBRARY}")
else()
    message(WARNING "Testing dependency libcheck not found. Tests will not be built.")
endif()

# OpenSSL (required only when AT_ZTA is ON)
if(AT_ZTA)
    find_package(OpenSSL REQUIRED)
    if(OPENSSL_FOUND)
        message("-- Found OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_LIBRARIES}")
    else()
        message(FATAL_ERROR "AT_ZTA=ON requires OpenSSL. Install libssl-dev.")
    endif()
endif()

set(DEPENDENCIES
    ${LIBUUID_LIBRARY}
    ${LIBSODIUM_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${LIBPROTOBUF_LIBRARY}
    ${LIBPROTOBUF_C_LIBRARY}
    ${LIBJANSSON_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    m
)

if(AT_ZTA)
    list(APPEND DEPENDENCIES OpenSSL::SSL OpenSSL::Crypto)
endif()

# Expose DEPENDENCIES to parent scope so examples/ can link them — but only
# when actually built via add_subdirectory(); a standalone build has no parent.
get_directory_property(_has_parent PARENT_DIRECTORY)
if(_has_parent)
    set(DEPENDENCIES "${DEPENDENCIES}" PARENT_SCOPE)
endif()

set(TEST_DEPENDENCIES ${DEPENDENCIES})
if(LIBCHECK_LIBRARY)
    list(APPEND TEST_DEPENDENCIES ${LIBCHECK_LIBRARY})
endif()


####################
# sources

set(top_src_dir ${CMAKE_CURRENT_SOURCE_DIR}/../..)

set(PROTO_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../protobuf")
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/protobuf")

set(protos
    autonomous_trust/core/protobuf/algorithms/agreement.proto
    autonomous_trust/core/protobuf/identity/history.proto
    autonomous_trust/core/protobuf/identity/identity.proto
    autonomous_trust/core/protobuf/identity/protocol.proto
    autonomous_trust/core/protobuf/negotiation/task.proto
    autonomous_trust/core/protobuf/processes/capabilities.proto
    autonomous_trust/core/protobuf/structures/dag.proto
    autonomous_trust/core/protobuf/structures/data.proto
    autonomous_trust/core/protobuf/structures/datetime.proto
    autonomous_trust/core/protobuf/structures/map.proto
    autonomous_trust/core/protobuf/structures/merkle.proto
    autonomous_trust/core/protobuf/fleet/update_proposal.proto
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
    autonomous_trust/node.c
    autonomous_trust/algorithms/agreement.c
    autonomous_trust/algorithms/paxos.c
    autonomous_trust/config/configuration.c
    autonomous_trust/config/discover.c
    autonomous_trust/config/names.c
    autonomous_trust/identity/encryptor.c
    autonomous_trust/identity/group.c
    autonomous_trust/identity/hexlify.c
    autonomous_trust/identity/history.c
    autonomous_trust/identity/identity.c
    autonomous_trust/identity/id_proc.c
    autonomous_trust/identity/peers.c
    autonomous_trust/identity/signature.c
    autonomous_trust/negotiation/task.c
    autonomous_trust/negotiation/negotiation.c
    autonomous_trust/negotiation/neg_proc.c
    autonomous_trust/reputation/reputation.c
    autonomous_trust/reputation/rep_proc.c
    autonomous_trust/config/generate.c
    autonomous_trust/network/ping.c
    autonomous_trust/network/ntp.c
    autonomous_trust/network/net_message.c
    autonomous_trust/network/net_proc.c
    autonomous_trust/network/network.c
    autonomous_trust/processes/capabilities.c
    autonomous_trust/processes/daemonize.c
    autonomous_trust/processes/process_tracker.c
    autonomous_trust/processes/processes.c
    autonomous_trust/structures/array.c
    autonomous_trust/structures/dag.c
    autonomous_trust/structures/data.c
    autonomous_trust/structures/datetime.c
    autonomous_trust/structures/map.c
    autonomous_trust/structures/merkle.c
    autonomous_trust/structures/redblack.c
    autonomous_trust/utilities/allocation.c
    autonomous_trust/utilities/b64.c
    autonomous_trust/utilities/err_str.c
    autonomous_trust/utilities/exception.c
    autonomous_trust/utilities/logger.c
    autonomous_trust/utilities/message.c
    autonomous_trust/utilities/msg_types.c
    autonomous_trust/utilities/protobuf_shutdown.cpp
    autonomous_trust/utilities/queue_pool.c
    autonomous_trust/utilities/sighandler.c
    autonomous_trust/utilities/util.c
    autonomous_trust/fleet/update_proposal.c
    autonomous_trust/fleet/fleet_helpers.c
    autonomous_trust/fleet/fleet_ops.c
    autonomous_trust/fleet/fleet_proc.c
    autonomous_trust/fleet/artifact_store.c
    autonomous_trust/fleet/artifact_proc_helpers.c
    autonomous_trust/fleet/artifact_proc.c
    autonomous_trust/fleet/update_proc_helpers.c
    autonomous_trust/fleet/update_selftest.c
    autonomous_trust/fleet/update_proc.c
    autonomous_trust/fleet/config_proc_helpers.c
    autonomous_trust/fleet/config_proc.c
)

# ZTA sources (only compiled when AT_ZTA is enabled)
if(AT_ZTA)
    list(APPEND libsrc
        autonomous_trust/zta/zta_verifier.c
        autonomous_trust/zta/x509_verifier.c
        autonomous_trust/zta/oidc_verifier.c
        autonomous_trust/zta/zta_policy.c
        autonomous_trust/zta/zta_audit.c
        autonomous_trust/zta/zta_process.c
    )
endif()

set(libhdr
    autonomous_trust.h
    autonomous_trust/algorithms/agreement.h
    autonomous_trust/algorithms/algorithms.h
    autonomous_trust/algorithms/paxos.h
    autonomous_trust/config/configuration.h
    autonomous_trust/config/discover.h
    autonomous_trust/config/names.h
    autonomous_trust/identity/history.h
    autonomous_trust/identity/identity.h
    autonomous_trust/identity/peers.h
    autonomous_trust/network/net_message.h
    autonomous_trust/processes/capabilities.h
    autonomous_trust/structures/array.h
    autonomous_trust/structures/dag.h
    autonomous_trust/structures/data.h
    autonomous_trust/structures/datetime.h
    autonomous_trust/structures/map.h
    autonomous_trust/structures/merkle.h
    autonomous_trust/utilities/exception.h
    autonomous_trust/utilities/logger.h
    autonomous_trust/utilities/message.h
    autonomous_trust/utilities/msg_types.h
    autonomous_trust/utilities/queue_pool.h
    autonomous_trust/utilities/sighandler.h
    autonomous_trust/negotiation/negotiation.h
    autonomous_trust/reputation/reputation.h
    autonomous_trust/config/generate.h
    autonomous_trust/network/ping.h
    autonomous_trust/network/ntp.h
    autonomous_trust/fleet/update_proposal.h
    autonomous_trust/fleet/fleet_proc.h
    autonomous_trust/fleet/artifact_store.h
    autonomous_trust/fleet/artifact_proc.h
    autonomous_trust/fleet/update_proc.h
    autonomous_trust/fleet/config_proc.h
)

if(AT_ZTA)
    list(APPEND libhdr
        autonomous_trust/zta/zta_verifier.h
        autonomous_trust/zta/x509_verifier.h
        autonomous_trust/zta/oidc_verifier.h
        autonomous_trust/zta/zta_policy.h
        autonomous_trust/zta/zta_audit.h
        autonomous_trust/zta/zta_process.h
        autonomous_trust/zta/zta_protocol.h
    )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust)

####################
# get latest version

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust/version.h)
    if(REVISION)
        message("-- Using provided REVISION: ${REVISION}")
        set(VERSION ${REVISION})
    else()
        find_package(Git)
        if (GIT_FOUND AND EXISTS "${top_src_dir}/.git")
            execute_process(COMMAND ${GIT_EXECUTABLE} describe HEAD OUTPUT_VARIABLE TAG OUTPUT_STRIP_TRAILING_WHITESPACE)
            string(REGEX REPLACE "^v" "" VERSION ${TAG})
            set(REVISION ${VERSION} CACHE STRING "git tag" FORCE)
        else()
            message(WARNING "Git not found, cannot set version info")
            set(VERSION "unknown")
            set(REVISION "unknown")
        endif()
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
    set(_exclude_args)                                                                                      
    if(NOT AT_ZTA)                                              
        list(APPEND _exclude_args --exclude zta)                                                            
    endif()      
    add_custom_command(
        OUTPUT ${_header_file}
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/preprocess.py ${_fullpath} ${_header_file} ${_src_dir}/ autonomous_trust ${_exclude_args}
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
        DEPENDS ${_full_proto} ${LIBPROTOBUF_C_LIBRARY} ${LIBPROTOBUF_LIBRARY} # ${PROTOC_C_EXE}
        VERBATIM
    )
    set(proto_c_src ${proto_c_src} ${_pb_c_src} PARENT_SCOPE)
endfunction()

## generate a Python source
# FIXME remove
function(protoc_py_gen _proto _full_proto _dir)
    get_filename_component(_base ${_proto} NAME_WE)
    set(_pb_py_src ${PROTO_BINARY_DIR}/${_dir}/${_base}.pb2.py)
    add_custom_command(
        OUTPUT ${_pb_py_src}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_SOURCE_DIR}/py
        COMMAND ${Protobuf_PROTOC_EXECUTABLE} --python_out=${PROTO_SOURCE_DIR}/py -I${PROTOBUF_INCLUDE_DIR} -I${PROTO_SOURCE_DIR} ${_full_proto}
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
    #protoc_py_gen(${_proto} ${_fullproto} ${_dir})
    set(proto_rel ${proto_rel} proto/${_proto})
endforeach()

## apply C generator to Google proto files
foreach(_proto ${google_protos})
    # assumes relative path (google/protobuf/smthg.proto)
    get_filename_component(_dir ${_proto} DIRECTORY)
    set(_fullproto ${PROTOBUF_INCLUDE_DIR}/${_proto})
    protoc_c_gen(${_proto} ${_fullproto} ${_dir})
endforeach()

include_directories(${PROTO_BINARY_DIR} ${PROTO_BINARY_DIR}/autonomous_trust/core/protobuf)

## Python will not be built without specifying this target
add_custom_target(proto_python DEPENDS ${proto_py_src})


####################
# create libraries

# When AT_ZTA is enabled, ALL targets must see AT_ZTA_ENABLED because it
# changes the size of public_identity_t (adds ZTA credential fields).
# A struct size mismatch between the library and consumers causes crashes.
if(AT_ZTA)
    add_compile_definitions(AT_ZTA_ENABLED)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

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
# Export library targets so examples/ can find them via add_subdirectory()
# (demo and example executables live under examples/, not here)



####################
# tests (only built when libcheck is available)
#
# Test executables link against the static library archive.  With AT_ZTA=ON
# the msg_types.c object acquires new dependencies on ZTA + proto symbols.
# A single-pass linker may fail to resolve them because it only scans the
# archive once.  Wrapping in --start-group/--end-group allows multiple passes.
set(AT_TEST_LIBS -Wl,--start-group autonomous_trust_static ${TEST_DEPENDENCIES} -Wl,--end-group)

if(LIBCHECK_LIBRARY)

add_executable(array_test test/array_test.c)
set_source_files_properties(test/array_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(array_test PRIVATE ${AT_TEST_LIBS})

add_executable(exception_test test/exception_test.c)
set_source_files_properties(test/exception_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(exception_test PRIVATE ${AT_TEST_LIBS})

add_executable(logger_test test/logging_test.c)
set_source_files_properties(test/logging_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(logger_test PRIVATE ${AT_TEST_LIBS})

add_executable(map_test test/map_test.c)
set_source_files_properties(test/map_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(map_test PRIVATE ${AT_TEST_LIBS})

add_executable(msg_test test/messaging_test.c)
set_source_files_properties(test/messaging_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(msg_test PRIVATE ${AT_TEST_LIBS})

add_executable(proc_track_test test/proc_track_test.c)
set_source_files_properties(test/proc_track_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(proc_track_test PRIVATE ${AT_TEST_LIBS})

add_executable(rb_test test/rb_test.c)
set_source_files_properties(test/rb_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(rb_test PRIVATE ${AT_TEST_LIBS})

add_executable(merkle_test test/merkle_test.c)
set_source_files_properties(test/merkle_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(merkle_test PRIVATE ${AT_TEST_LIBS})

add_executable(dag_test test/dag_test.c)
set_source_files_properties(test/dag_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(dag_test PRIVATE ${AT_TEST_LIBS})

add_executable(agreement_test test/agreement_test.c)
set_source_files_properties(test/agreement_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(agreement_test PRIVATE ${AT_TEST_LIBS})

add_executable(net_message_test test/net_message_test.c)
set_source_files_properties(test/net_message_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(net_message_test PRIVATE ${AT_TEST_LIBS})

add_executable(negotiation_test test/negotiation_test.c)
set_source_files_properties(test/negotiation_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(negotiation_test PRIVATE ${AT_TEST_LIBS} m)

add_executable(reputation_test test/reputation_test.c)
set_source_files_properties(test/reputation_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(reputation_test PRIVATE ${AT_TEST_LIBS} m)

add_executable(history_test test/history_test.c)
set_source_files_properties(test/history_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(history_test PRIVATE ${AT_TEST_LIBS})

add_executable(queue_pool_test test/queue_pool_test.c)
set_source_files_properties(test/queue_pool_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(queue_pool_test PRIVATE ${AT_TEST_LIBS})

add_executable(network_test test/network_test.c)
set_source_files_properties(test/network_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(network_test PRIVATE ${AT_TEST_LIBS})

add_executable(identity_test test/identity_test.c)
set_source_files_properties(test/identity_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(identity_test PRIVATE ${AT_TEST_LIBS})

add_executable(data_test test/data_test.c)
set_source_files_properties(test/data_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(data_test PRIVATE ${AT_TEST_LIBS})

add_executable(datetime_test test/datetime_test.c)
set_source_files_properties(test/datetime_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(datetime_test PRIVATE ${AT_TEST_LIBS})

add_executable(b64_test test/b64_test.c)
set_source_files_properties(test/b64_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(b64_test PRIVATE ${AT_TEST_LIBS})

add_executable(group_test test/group_test.c)
set_source_files_properties(test/group_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(group_test PRIVATE ${AT_TEST_LIBS})

add_executable(data_json_test test/data_json_test.c)
set_source_files_properties(test/data_json_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(data_json_test PRIVATE ${AT_TEST_LIBS})

add_executable(datetime2_test test/datetime2_test.c)
set_source_files_properties(test/datetime2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(datetime2_test PRIVATE ${AT_TEST_LIBS})

add_executable(config_test test/config_test.c)
set_source_files_properties(test/config_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(config_test PRIVATE ${AT_TEST_LIBS})

add_executable(reputation2_test test/reputation2_test.c)
set_source_files_properties(test/reputation2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(reputation2_test PRIVATE ${AT_TEST_LIBS})

add_executable(map_json_test test/map_json_test.c)
set_source_files_properties(test/map_json_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(map_json_test PRIVATE ${AT_TEST_LIBS})

add_executable(array2_test test/array2_test.c)
set_source_files_properties(test/array2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(array2_test PRIVATE ${AT_TEST_LIBS})

add_executable(negotiation2_test test/negotiation2_test.c)
set_source_files_properties(test/negotiation2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(negotiation2_test PRIVATE ${AT_TEST_LIBS})

enable_testing()

add_test(NAME array_test COMMAND $<TARGET_FILE:array_test>)
add_test(NAME exception_test COMMAND $<TARGET_FILE:exception_test>)
add_test(NAME logger_test COMMAND $<TARGET_FILE:logger_test>)
add_test(NAME map_test COMMAND $<TARGET_FILE:map_test>)
add_test(NAME msg_test COMMAND $<TARGET_FILE:msg_test>)
add_test(NAME proc_track_test COMMAND $<TARGET_FILE:proc_track_test>)
add_test(NAME rb_test COMMAND $<TARGET_FILE:rb_test>)
add_test(NAME merkle_test COMMAND $<TARGET_FILE:merkle_test>)
add_test(NAME dag_test COMMAND $<TARGET_FILE:dag_test>)
add_test(NAME agreement_test COMMAND $<TARGET_FILE:agreement_test>)
add_test(NAME net_message_test COMMAND $<TARGET_FILE:net_message_test>)
add_test(NAME negotiation_test COMMAND $<TARGET_FILE:negotiation_test>)
add_test(NAME reputation_test COMMAND $<TARGET_FILE:reputation_test>)
add_test(NAME history_test COMMAND $<TARGET_FILE:history_test>)
add_test(NAME queue_pool_test COMMAND $<TARGET_FILE:queue_pool_test>)
add_test(NAME network_test COMMAND $<TARGET_FILE:network_test>)
add_test(NAME identity_test COMMAND $<TARGET_FILE:identity_test>)
add_test(NAME data_test COMMAND $<TARGET_FILE:data_test>)
add_test(NAME datetime_test COMMAND $<TARGET_FILE:datetime_test>)
add_test(NAME b64_test COMMAND $<TARGET_FILE:b64_test>)
add_test(NAME group_test COMMAND $<TARGET_FILE:group_test>)
add_test(NAME data_json_test COMMAND $<TARGET_FILE:data_json_test>)
add_test(NAME datetime2_test COMMAND $<TARGET_FILE:datetime2_test>)
add_test(NAME config_test COMMAND $<TARGET_FILE:config_test>)
add_test(NAME reputation2_test COMMAND $<TARGET_FILE:reputation2_test>)
add_test(NAME map_json_test COMMAND $<TARGET_FILE:map_json_test>)
add_test(NAME array2_test COMMAND $<TARGET_FILE:array2_test>)
add_test(NAME negotiation2_test COMMAND $<TARGET_FILE:negotiation2_test>)

add_executable(msg_types_test test/msg_types_test.c)
set_source_files_properties(test/msg_types_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(msg_types_test PRIVATE ${AT_TEST_LIBS})

add_executable(network2_test test/network2_test.c)
set_source_files_properties(test/network2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(network2_test PRIVATE ${AT_TEST_LIBS})

add_executable(proc_tracker2_test test/proc_tracker2_test.c)
set_source_files_properties(test/proc_tracker2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(proc_tracker2_test PRIVATE ${AT_TEST_LIBS})

add_executable(processes_test test/processes_test.c)
set_source_files_properties(test/processes_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(processes_test PRIVATE ${AT_TEST_LIBS})

add_executable(capabilities_test test/capabilities_test.c)
set_source_files_properties(test/capabilities_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(capabilities_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME msg_types_test COMMAND $<TARGET_FILE:msg_types_test>)
add_test(NAME network2_test COMMAND $<TARGET_FILE:network2_test>)
add_test(NAME proc_tracker2_test COMMAND $<TARGET_FILE:proc_tracker2_test>)
add_test(NAME processes_test COMMAND $<TARGET_FILE:processes_test>)
add_test(NAME capabilities_test COMMAND $<TARGET_FILE:capabilities_test>)

add_executable(util_test test/util_test.c)
set_source_files_properties(test/util_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(util_test PRIVATE ${AT_TEST_LIBS})

add_executable(err_str_test test/err_str_test.c)
set_source_files_properties(test/err_str_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(err_str_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME util_test COMMAND $<TARGET_FILE:util_test>)
add_test(NAME err_str_test COMMAND $<TARGET_FILE:err_str_test>)

add_executable(message_test test/message_test.c)
set_source_files_properties(test/message_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(message_test PRIVATE ${AT_TEST_LIBS})

add_executable(rb2_test test/rb2_test.c)
set_source_files_properties(test/rb2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(rb2_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME message_test COMMAND $<TARGET_FILE:message_test>)
add_test(NAME rb2_test COMMAND $<TARGET_FILE:rb2_test>)

add_executable(map2_test test/map2_test.c)
set_source_files_properties(test/map2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(map2_test PRIVATE ${AT_TEST_LIBS})

add_executable(reputation3_test test/reputation3_test.c)
set_source_files_properties(test/reputation3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(reputation3_test PRIVATE ${AT_TEST_LIBS})

add_executable(config2_test test/config2_test.c)
set_source_files_properties(test/config2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(config2_test PRIVATE ${AT_TEST_LIBS})

add_executable(util2_test test/util2_test.c)
set_source_files_properties(test/util2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(util2_test PRIVATE ${AT_TEST_LIBS})

add_executable(msg_types2_test test/msg_types2_test.c)
set_source_files_properties(test/msg_types2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(msg_types2_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME map2_test COMMAND $<TARGET_FILE:map2_test>)
add_test(NAME reputation3_test COMMAND $<TARGET_FILE:reputation3_test>)
add_test(NAME config2_test COMMAND $<TARGET_FILE:config2_test>)
add_test(NAME util2_test COMMAND $<TARGET_FILE:util2_test>)
add_test(NAME msg_types2_test COMMAND $<TARGET_FILE:msg_types2_test>)

add_executable(msg_types3_test test/msg_types3_test.c)
set_source_files_properties(test/msg_types3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(msg_types3_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME msg_types3_test COMMAND $<TARGET_FILE:msg_types3_test>)

add_executable(task_proto_test test/task_proto_test.c)
set_source_files_properties(test/task_proto_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(task_proto_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME task_proto_test COMMAND $<TARGET_FILE:task_proto_test>)

add_executable(paxos_test test/paxos_test.c)
set_source_files_properties(test/paxos_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(paxos_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME paxos_test COMMAND $<TARGET_FILE:paxos_test>)

# Critical and Major regression tests have been folded into the per-module
# test files (array_test, array2_test, paxos_test, msg_types2_test,
# identity2_test, config_test, group2_test).

add_executable(update_proposal_test test/update_proposal_test.c)
set_source_files_properties(test/update_proposal_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(update_proposal_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME update_proposal_test COMMAND $<TARGET_FILE:update_proposal_test>)

# Fleet tests compile their own .c files (not via the library), so they need
# proto and table headers to exist before compilation starts.  Depend on the
# static library target which already generates both.
#
# Fleet .c files call helpers from autonomous_trust/utilities/util.c
# (path_join, makedirs, min/max, strremove).  Pulling those from the static
# archive would cause duplicate-symbol conflicts against the directly-
# compiled fleet sources, so compile util.c into each fleet test instead.
set(fleet_test_util_srcs
    autonomous_trust/utilities/util.c
    autonomous_trust/utilities/exception.c)

add_executable(fleet_proc_test
    test/fleet_proc_test.c
    autonomous_trust/fleet/fleet_helpers.c
    autonomous_trust/fleet/update_proposal.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/fleet_proc_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(fleet_proc_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(fleet_proc_test autonomous_trust_static)

add_test(NAME fleet_proc_test COMMAND $<TARGET_FILE:fleet_proc_test>)

add_executable(artifact_store_test
    test/artifact_store_test.c
    autonomous_trust/fleet/artifact_store.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/artifact_store_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(artifact_store_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(artifact_store_test autonomous_trust_static)

add_test(NAME artifact_store_test COMMAND $<TARGET_FILE:artifact_store_test>)

add_executable(artifact_proc_test
    test/artifact_proc_test.c
    autonomous_trust/fleet/artifact_proc_helpers.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/artifact_proc_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(artifact_proc_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(artifact_proc_test autonomous_trust_static)

add_test(NAME artifact_proc_test COMMAND $<TARGET_FILE:artifact_proc_test>)

add_executable(update_proc_test
    test/update_proc_test.c
    autonomous_trust/fleet/update_proc_helpers.c
    autonomous_trust/fleet/update_selftest.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/update_proc_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(update_proc_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(update_proc_test autonomous_trust_static)

add_test(NAME update_proc_test COMMAND $<TARGET_FILE:update_proc_test>)

add_executable(config_proc_test
    test/config_proc_test.c
    autonomous_trust/fleet/config_proc_helpers.c
    autonomous_trust/fleet/update_proc_helpers.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/config_proc_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(config_proc_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(config_proc_test autonomous_trust_static)

add_test(NAME config_proc_test COMMAND $<TARGET_FILE:config_proc_test>)

add_executable(util3_test test/util3_test.c)
set_source_files_properties(test/util3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(util3_test PRIVATE ${AT_TEST_LIBS})

add_executable(capabilities2_test test/capabilities2_test.c)
set_source_files_properties(test/capabilities2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(capabilities2_test PRIVATE ${AT_TEST_LIBS})

add_executable(identity2_test test/identity2_test.c)
set_source_files_properties(test/identity2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(identity2_test PRIVATE ${AT_TEST_LIBS})

add_executable(group2_test test/group2_test.c)
set_source_files_properties(test/group2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(group2_test PRIVATE ${AT_TEST_LIBS})

add_executable(map3_test test/map3_test.c)
set_source_files_properties(test/map3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(map3_test PRIVATE ${AT_TEST_LIBS})

add_executable(data_proto_test test/data_proto_test.c)
set_source_files_properties(test/data_proto_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(data_proto_test PRIVATE ${AT_TEST_LIBS})

add_executable(array3_test test/array3_test.c)
set_source_files_properties(test/array3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(array3_test PRIVATE ${AT_TEST_LIBS})

add_executable(message2_test test/message2_test.c)
set_source_files_properties(test/message2_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(message2_test PRIVATE ${AT_TEST_LIBS})

add_executable(capabilities3_test test/capabilities3_test.c)
set_source_files_properties(test/capabilities3_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(capabilities3_test PRIVATE ${AT_TEST_LIBS})

add_test(NAME util3_test COMMAND $<TARGET_FILE:util3_test>)
add_test(NAME capabilities2_test COMMAND $<TARGET_FILE:capabilities2_test>)
add_test(NAME identity2_test COMMAND $<TARGET_FILE:identity2_test>)
add_test(NAME group2_test COMMAND $<TARGET_FILE:group2_test>)
add_test(NAME map3_test COMMAND $<TARGET_FILE:map3_test>)
add_test(NAME data_proto_test COMMAND $<TARGET_FILE:data_proto_test>)
add_test(NAME array3_test COMMAND $<TARGET_FILE:array3_test>)
add_test(NAME message2_test COMMAND $<TARGET_FILE:message2_test>)
add_test(NAME capabilities3_test COMMAND $<TARGET_FILE:capabilities3_test>)

# ZTA tests (only when AT_ZTA is enabled)
if(AT_ZTA)
    add_executable(zta_verifier_test test/zta_verifier_test.c)
    set_source_files_properties(test/zta_verifier_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(zta_verifier_test PRIVATE ${AT_TEST_LIBS})

    add_executable(zta_policy_test test/zta_policy_test.c)
    set_source_files_properties(test/zta_policy_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(zta_policy_test PRIVATE ${AT_TEST_LIBS})

    add_executable(zta_audit_test test/zta_audit_test.c)
    set_source_files_properties(test/zta_audit_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(zta_audit_test PRIVATE ${AT_TEST_LIBS})

    add_executable(zta_ocsp_test test/zta_ocsp_test.c)
    set_source_files_properties(test/zta_ocsp_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_compile_definitions(zta_ocsp_test PRIVATE
        GEN_CA_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/test/zta_test_ca/generate_test_ca.sh")
    target_link_libraries(zta_ocsp_test PRIVATE ${AT_TEST_LIBS})

    add_executable(zta_delegation_test test/zta_delegation_test.c)
    set_source_files_properties(test/zta_delegation_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(zta_delegation_test PRIVATE ${AT_TEST_LIBS})

    add_test(NAME zta_verifier_test COMMAND $<TARGET_FILE:zta_verifier_test>)
    add_test(NAME zta_policy_test COMMAND $<TARGET_FILE:zta_policy_test>)
    add_test(NAME zta_audit_test COMMAND $<TARGET_FILE:zta_audit_test>)
    add_test(NAME zta_ocsp_test COMMAND $<TARGET_FILE:zta_ocsp_test>)
    add_test(NAME zta_delegation_test COMMAND $<TARGET_FILE:zta_delegation_test>)
endif() # AT_ZTA

endif() # LIBCHECK_LIBRARY

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

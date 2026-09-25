# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

# libat_dtn: the DTN / Bundle Protocol transport as an extension library
# (FEATURE_SPLIT_PLAN Phase 1; see at-over-dtn.md and
# doc/architecture/extensions.md). Reached from the core CMakeLists.txt with
# add_subdirectory when AT_NET_DTN is ON, after the core targets and
# AT_TEST_LIBS exist, so the core's include dirs, compile flags and
# dependency lists are inherited here.
#
# The library registers the "dtn_bp" transport and process runner from
# constructors (net_transport_dtn.c), so the core names neither. It includes
# the core's private headers (net_proc_priv.h, process_t) and must therefore
# be built by this same project with the same flags.
#
#   at_dtn         SHARED, linked against libautonomous_trust.so
#   at_dtn_static  STATIC (libat_dtn.a), for static consumers, which link it
#                  with --whole-archive or call at_dtn_link()

# Which BP backend to link. Each implements dtn_backend.h.
set(AT_NET_DTN_BACKEND "stub" CACHE STRING "BP library backend: stub | ion | ud3tn | ud3tnv2")
set_property(CACHE AT_NET_DTN_BACKEND PROPERTY STRINGS stub ion ud3tn ud3tnv2)

set(AT_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(at_dtn_src
    dtn_eid.c
    net_transport_dtn.c
)
set(at_dtn_inc)
set(at_dtn_libs)
set(at_dtn_deps)

if(AT_NET_DTN_BACKEND STREQUAL "stub")
    # No-op backend: lets AT_NET_DTN=ON build without a BP library.
    list(APPEND at_dtn_src dtn_backend_stub.c)
elseif(AT_NET_DTN_BACKEND STREQUAL "ion")
    # NASA ION bp_* API. Two modes:
    #   (a) Submodule present at src/c/third_party/ION-DTN — we build it
    #       via autotools into a build-local prefix. No sudo required.
    #   (b) Submodule absent — fall back to system-installed ION (or
    #       paths supplied explicitly via -DION_* cache vars).
    # The node's local EID must be pre-provisioned via bpadmin before
    # the transport is used at runtime.
    set(ION_SUBMODULE ${AT_C_DIR}/third_party/ION-DTN)
    set(ION_PREFIX    ${CMAKE_BINARY_DIR}/ion-install)

    if(EXISTS ${ION_SUBMODULE}/configure.ac)
        message("-- ION: building from submodule into ${ION_PREFIX}")

        # Surface autotools-missing failures at CMake-configure time
        # with a useful message, rather than a cryptic build-time error.
        find_program(AUTORECONF_EXEC autoreconf)
        find_program(AUTOMAKE_EXEC   automake)
        find_program(LIBTOOLIZE_EXEC NAMES libtoolize glibtoolize)
        if(NOT AUTORECONF_EXEC OR NOT AUTOMAKE_EXEC OR NOT LIBTOOLIZE_EXEC)
            message(FATAL_ERROR
                "AT_NET_DTN_BACKEND=ion needs autotools to build the submodule. "
                "Install: sudo apt-get install -y autoconf automake libtool pkg-config libexpat1-dev")
        endif()

        include(ExternalProject)
        include(ProcessorCount)
        ProcessorCount(ION_PARALLEL)
        if(ION_PARALLEL EQUAL 0)
            set(ION_PARALLEL 1)
        endif()

        # BUILD_IN_SOURCE because ION's autotools setup does not cleanly
        # support out-of-tree builds. Artifacts land inside the submodule
        # checkout under third_party/ION-DTN (its own .gitignore covers them).
        ExternalProject_Add(ion_external
            SOURCE_DIR        ${ION_SUBMODULE}
            BUILD_IN_SOURCE   1
            CONFIGURE_COMMAND
                sh -c "cd <SOURCE_DIR> && (make distclean 2>/dev/null || true) && rm -f *.la libtool config.status && autoreconf -fi && ./configure --prefix=${ION_PREFIX} --enable-shared --disable-static"
            BUILD_COMMAND
                make -C <SOURCE_DIR> -j${ION_PARALLEL}
            INSTALL_COMMAND
                make -C <SOURCE_DIR> install
            BUILD_BYPRODUCTS
                ${ION_PREFIX}/lib/libbp${CMAKE_SHARED_LIBRARY_SUFFIX}
                ${ION_PREFIX}/lib/libici${CMAKE_SHARED_LIBRARY_SUFFIX}
            LOG_CONFIGURE 1
            LOG_BUILD     1
            LOG_INSTALL   1
        )
        # Pre-create the include dir so the include path below has
        # something to add even before the first build runs.
        file(MAKE_DIRECTORY ${ION_PREFIX}/include)
        set(ION_INCLUDE_DIR ${ION_PREFIX}/include)
        set(ION_BP_LIB  ${ION_PREFIX}/lib/libbp${CMAKE_SHARED_LIBRARY_SUFFIX})
        set(ION_ICI_LIB ${ION_PREFIX}/lib/libici${CMAKE_SHARED_LIBRARY_SUFFIX})
        # ION must be installed (libs + headers) before dtn_backend_ion.c
        # compiles, or #include <bp.h> fails.
        list(APPEND at_dtn_deps ion_external)
        # RPATH so libat_dtn and the DTN tests find the in-build ION shared
        # libs at runtime without LD_LIBRARY_PATH.
        list(APPEND CMAKE_BUILD_RPATH   ${ION_PREFIX}/lib)
        list(APPEND CMAKE_INSTALL_RPATH ${ION_PREFIX}/lib)
    else()
        find_path(ION_INCLUDE_DIR bp.h PATH_SUFFIXES ion)
        find_library(ION_BP_LIB  NAMES bp)
        find_library(ION_ICI_LIB NAMES ici)
        if(NOT ION_INCLUDE_DIR OR NOT ION_BP_LIB OR NOT ION_ICI_LIB)
            message(FATAL_ERROR
                "AT_NET_DTN_BACKEND=ion selected but the ION-DTN submodule is missing "
                "AND no system install was found. Fix one of:\n"
                "  git submodule update --init src/c/third_party/ION-DTN\n"
                "  sudo make install (in a cloned ION-DTN)\n"
                "  cmake ... -DION_INCLUDE_DIR=... -DION_BP_LIB=... -DION_ICI_LIB=...")
        endif()
        message("-- Found ION bp at ${ION_BP_LIB}, ici at ${ION_ICI_LIB}")
    endif()

    list(APPEND at_dtn_src  dtn_backend_ion.c)
    list(APPEND at_dtn_inc  ${ION_INCLUDE_DIR})
    list(APPEND at_dtn_libs ${ION_BP_LIB} ${ION_ICI_LIB})
elseif(AT_NET_DTN_BACKEND STREQUAL "ud3tn")
    # uD3TN legacy AAP v1 binary protocol over Unix-socket or TCP — no
    # external library needed; the daemon must be reachable at runtime via
    # AT_DTN_UD3TN_SOCKET (e.g. "unix:./ud3tn.aap.socket" or "tcp:host:port").
    list(APPEND at_dtn_src dtn_backend_ud3tn.c)
elseif(AT_NET_DTN_BACKEND STREQUAL "ud3tnv2")
    # uD3TN AAP 2.0: protobuf-delimited framing. The schema, proto/aap2.proto,
    # is a symlink to the ud3tn submodule's
    # components/aap2/aap2.proto (https://gitlab.com/d3tn/ud3tn).
    #
    # Codegen is a standalone protoc-c run — not the core's `protos` list,
    # because aap2.proto is not under the AT protobuf/ root. Generated
    # sources land in the build tree.
    set(AAP2_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
    set(AAP2_GEN_DIR   ${CMAKE_CURRENT_BINARY_DIR}/proto)
    add_custom_command(
        OUTPUT ${AAP2_GEN_DIR}/aap2.pb-c.c ${AAP2_GEN_DIR}/aap2.pb-c.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${AAP2_GEN_DIR}
        COMMAND ${Protobuf_PROTOC_EXECUTABLE}
            --c_out=${AAP2_GEN_DIR}
            -I${AAP2_PROTO_DIR}
            ${AAP2_PROTO_DIR}/aap2.proto
        COMMENT "Generating protobuf-c sources for aap2.proto"
        DEPENDS ${AAP2_PROTO_DIR}/aap2.proto
        VERBATIM
    )
    list(APPEND at_dtn_src dtn_backend_ud3tnv2.c ${AAP2_GEN_DIR}/aap2.pb-c.c)
    list(APPEND at_dtn_inc ${AAP2_GEN_DIR})
else()
    message(FATAL_ERROR "Unknown AT_NET_DTN_BACKEND: ${AT_NET_DTN_BACKEND}")
endif()

add_library(at_dtn SHARED ${at_dtn_src})
# Link the core .so by file, not by target: the core's target_sources(...
# PUBLIC ${libsrc}) would otherwise compile a second copy of the whole core
# into libat_dtn, with its own process and transport tables.
target_link_libraries(at_dtn PRIVATE $<TARGET_LINKER_FILE:autonomous_trust> ${at_dtn_libs})
add_dependencies(at_dtn autonomous_trust)

add_library(at_dtn_static STATIC ${at_dtn_src})
set_target_properties(at_dtn_static PROPERTIES OUTPUT_NAME at_dtn)
target_link_libraries(at_dtn_static INTERFACE ${at_dtn_libs})
# Static: nothing links the core in, but its generated headers must exist.
add_dependencies(at_dtn_static autonomous_trust_static)

foreach(_t at_dtn at_dtn_static)
    set_target_properties(${_t} PROPERTIES COMPILE_FLAGS "${lib_compile_flags}")
    target_include_directories(${_t} PRIVATE ${at_dtn_inc})
    if(at_dtn_deps)
        add_dependencies(${_t} ${at_dtn_deps})
    endif()
endforeach()

install(TARGETS at_dtn at_dtn_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

####################
# tests (only built when libcheck is available)
#
# A test links the extension whole, then the core group, so DTN's
# registration constructors are in the binary and resolve against the core.
if(LIBCHECK_LIBRARY)
    set(AT_DTN_TEST_LIBS
        -Wl,--whole-archive at_dtn_static -Wl,--no-whole-archive
        ${at_dtn_libs} ${AT_TEST_LIBS})

    function(add_dtn_test name)
        add_executable(${name} test/${name}.c)
        set_source_files_properties(test/${name}.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_include_directories(${name} PRIVATE ${AT_C_DIR}/test)
        target_link_libraries(${name} PRIVATE ${AT_DTN_TEST_LIBS})
        add_test(NAME ${name} COMMAND $<TARGET_FILE:${name}>)
    endfunction()

    # dtn_eid_test is pure string math, so it runs against any backend.
    # dtn_link_test pins that linking the extension registers the transport
    # and runner (FEATURE_SPLIT_PLAN §5.3).
    add_dtn_test(dtn_eid_test)
    add_dtn_test(dtn_link_test)
    # dtn_transport_test exercises the transport's send/recv paths through
    # the backend vtable; it assumes the no-op stub (send returns 0, recv
    # returns ENOMSG) and would misbehave against a real daemon.
    if(AT_NET_DTN_BACKEND STREQUAL "stub")
        add_dtn_test(dtn_transport_test)
    endif()
endif()

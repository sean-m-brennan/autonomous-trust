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

# virtiofs page-cache reconciliation hazard (sandbox builds): when the
# source/build trees live on virtiofs, gcc occasionally writes a .o with
# a corrupt section header table. The on-disk file is short of what
# ar/ranlib expect, so the bfd LTO plugin emits "ELF section name out
# of range" and the symbol is silently dropped from the static archive's
# TOC, breaking the eventual link. Detect virtiofs and install a
# validate-and-retry compiler launcher that re-invokes gcc on bad
# output. Off by default outside virtiofs (no false positives), and
# always overridable via -DAT_CC_VALIDATE_OUTPUT={ON,OFF}.
execute_process(
    COMMAND stat -f --format=%T ${CMAKE_BINARY_DIR}
    OUTPUT_VARIABLE _at_build_fs_type
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(_at_build_fs_type STREQUAL "fuseblk" OR
   _at_build_fs_type STREQUAL "virtiofs" OR
   _at_build_fs_type MATCHES "^9p")
    set(_at_validate_default ON)
else()
    set(_at_validate_default OFF)
endif()
option(AT_CC_VALIDATE_OUTPUT
    "Re-invoke the compiler when it emits a .o with a corrupt section header (virtiofs workaround)"
    ${_at_validate_default})
if(AT_CC_VALIDATE_OUTPUT)
    set(_at_cc_launcher ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cc-validate-output)
    if(NOT EXISTS ${_at_cc_launcher})
        message(FATAL_ERROR "AT_CC_VALIDATE_OUTPUT=ON but ${_at_cc_launcher} is missing")
    endif()
    set(CMAKE_C_COMPILER_LAUNCHER ${_at_cc_launcher})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${_at_cc_launcher})
    message("-- AT_CC_VALIDATE_OUTPUT enabled (build FS: ${_at_build_fs_type}); using ${_at_cc_launcher}")

    # Same virtiofs page-cache hazard, different victim: when ar/ranlib writes
    # libautonomous_trust.a through virtiofs, the on-disk file is occasionally
    # truncated at a page boundary (observed exactly 65536 bytes, leaving 5 of
    # 81 expected members). Downstream links then fail with undefined refs on
    # symbols whose .o was never persisted. Wrap ar+ranlib with a validate-
    # and-retry launcher analogous to cc-validate-output. Tied to the same
    # AT_CC_VALIDATE_OUTPUT switch since the trigger is identical (virtiofs).
    set(_at_ar_launcher ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ar-validate-output)
    if(NOT EXISTS ${_at_ar_launcher})
        message(FATAL_ERROR "AT_CC_VALIDATE_OUTPUT=ON but ${_at_ar_launcher} is missing")
    endif()
    set(CMAKE_C_ARCHIVE_CREATE
        "${_at_ar_launcher} ar <CMAKE_AR> qc <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH
        "${_at_ar_launcher} ranlib <CMAKE_RANLIB> <TARGET>")
    set(CMAKE_CXX_ARCHIVE_CREATE
        "${_at_ar_launcher} ar <CMAKE_AR> qc <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_FINISH
        "${_at_ar_launcher} ranlib <CMAKE_RANLIB> <TARGET>")
    message("-- AT_CC_VALIDATE_OUTPUT: wrapping ar/ranlib via ${_at_ar_launcher}")
endif()

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
    # conda's default CFLAGS are GCC-tuned (e.g. -fno-merge-constants) and leak
    # into CMAKE_C_FLAGS; clang ignores them but, under -Werror, the resulting
    # -Wignored-optimization-argument would otherwise fail the build.
    list(APPEND useful_warnings -Wno-ignored-optimization-argument)
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

# DTN / Bundle Protocol transport (see at-over-dtn.md). Adds the "dtn_bp"
# network transport and compiles a DTN-specific receiver path.
option(AT_NET_DTN "Enable DTN/Bundle-Protocol network transport" OFF)
# Which BP backend to link — currently only "stub" (no external deps);
# add ION / uD3TN backends by implementing dtn_backend.h and selecting here.
set(AT_NET_DTN_BACKEND "stub" CACHE STRING "BP library backend: stub | ion | ud3tn")
set_property(CACHE AT_NET_DTN_BACKEND PROPERTY STRINGS stub ion ud3tn)

# Plaintext forwarding envelope (see at-over-dtn.md §4.3, net_envelope.h).
# When ON, peer-to-peer wire frames carry a 36-byte plaintext routing header
# so gateway nodes can bridge transports without decrypting the inner payload.
# Default OFF so traffic on non-gateway deployments stays byte-for-byte
# compatible with pre-2b builds until net_proc.c opts into wrapping.
option(AT_NET_ENVELOPE "Enable plaintext forwarding envelope for gateway relay" OFF)

# Group UUID -> gateway leg routing for cross-group bridging
# (at-over-dtn.md §4.3 stage F). Gateway receives a GROUP-addressed envelope
# for a remote group UUID, looks up a configured leg, and re-emits via that
# leg. Requires AT_NET_ENVELOPE since envelope-less wire frames carry no
# destination UUID for the routing lookup.
option(AT_NET_GROUP_FORWARD "Enable group UUID -> gateway routing for cross-leg bridging" OFF)

# Cross-cluster peer discovery (at-over-dtn.md §4.3 stage E). When ON,
# gateway-forwarded ID_ANNOUNCE broadcasts carrying NET_ENV_FLAG_FORWARDED
# register the originating peer as a remote peer whose address is left as-is
# so the hybrid CIDR matcher routes replies back via the gateway. Requires
# AT_NET_ENVELOPE since the forwarding trust signal comes from the envelope
# flag byte.
option(AT_DISCOVERY_CROSS_CLUSTER "Enable cross-cluster peer discovery via gateway forwarding" OFF)

if(AT_NET_GROUP_FORWARD AND NOT AT_NET_ENVELOPE)
    message(FATAL_ERROR "AT_NET_GROUP_FORWARD=ON requires AT_NET_ENVELOPE=ON")
endif()

if(AT_DISCOVERY_CROSS_CLUSTER AND NOT AT_NET_ENVELOPE)
    message(FATAL_ERROR "AT_DISCOVERY_CROSS_CLUSTER=ON requires AT_NET_ENVELOPE=ON")
endif()

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
#
# When the conda env provides libprotobuf, pre-seed Protobuf_INCLUDE_DIR /
# Protobuf_LIBRARY / Protobuf_PROTOC_EXECUTABLE so FindProtobuf reads the
# *conda* headers for its version-extraction step. Without this, conda's
# cmake (4.x) lands on /usr/include/google/protobuf/stubs/common.h to
# extract the version, but its sysroot is the conda toolchain root — the
# /usr/include path is not readable through that sysroot, so `file
# STRINGS` fails and the subsequent math(EXPR) calls explode on the empty
# version string.
#
# If conda is active but lacks protobuf, fall through to a system search
# that bypasses find_package(Protobuf) entirely — we emulate the small
# subset of vars our build needs (INCLUDE_DIR/LIBRARY/PROTOC) using bare
# find_*, dodging the broken file STRINGS read.  Recommend `conda install
# protobuf libprotobuf` to stay inside the env.
set(_at_protobuf_resolved FALSE)
if(DEFINED ENV{CONDA_PREFIX})
    find_path(_at_protobuf_inc google/protobuf/stubs/common.h
              HINTS ${CONDA_ROOT} NO_DEFAULT_PATH)
    find_library(_at_protobuf_lib NAMES protobuf
                 HINTS ${CONDA_ROOT} NO_DEFAULT_PATH)
    find_program(_at_protoc_exe protoc HINTS ${CONDA_ROOT} NO_DEFAULT_PATH)
    if(_at_protobuf_inc AND _at_protobuf_lib)
        set(Protobuf_INCLUDE_DIR ${_at_protobuf_inc} CACHE PATH "" FORCE)
        set(Protobuf_LIBRARY ${_at_protobuf_lib} CACHE FILEPATH "" FORCE)
        if(_at_protoc_exe)
            set(Protobuf_PROTOC_EXECUTABLE ${_at_protoc_exe} CACHE FILEPATH "" FORCE)
        endif()
        find_package(Protobuf REQUIRED)
        set(_at_protobuf_resolved TRUE)
    else()
        # Conda has no protobuf — fall back to a bare-find of the system
        # copy.  Do NOT call find_package(Protobuf) here: conda's cmake
        # cannot read the system header through its sysroot and would
        # error out with `file STRINGS ... cannot be read`.
        find_path(_at_sys_protobuf_inc google/protobuf/stubs/common.h)
        find_library(_at_sys_protobuf_lib NAMES protobuf)
        find_program(_at_sys_protoc_exe protoc)
        if(_at_sys_protobuf_inc AND _at_sys_protobuf_lib)
            set(Protobuf_INCLUDE_DIR  ${_at_sys_protobuf_inc} CACHE PATH "" FORCE)
            set(Protobuf_INCLUDE_DIRS ${_at_sys_protobuf_inc})
            set(Protobuf_LIBRARY      ${_at_sys_protobuf_lib} CACHE FILEPATH "" FORCE)
            set(Protobuf_LIBRARIES    ${_at_sys_protobuf_lib})
            if(_at_sys_protoc_exe)
                set(Protobuf_PROTOC_EXECUTABLE ${_at_sys_protoc_exe} CACHE FILEPATH "" FORCE)
            endif()
            message(STATUS "Conda has no protobuf; using system at ${_at_sys_protobuf_lib} "
                           "(install `protobuf libprotobuf` into the conda env to silence this)")
            set(_at_protobuf_resolved TRUE)
        endif()
    endif()
endif()
if(NOT _at_protobuf_resolved)
    find_package(Protobuf REQUIRED)
endif()
include_directories(${Protobuf_INCLUDE_DIRS})
if(Protobuf_LIBRARY)
    message("-- Found libprotobuf at ${Protobuf_LIBRARY}")
else()
    message(FATAL_ERROR "Required dependency libprotobuf not found.")
endif()

# Legacy uppercase alias.  The system cmake 3.31 FindProtobuf still
# back-fills PROTOBUF_INCLUDE_DIR from Protobuf_INCLUDE_DIR, but conda's
# cmake 4.x dropped that fallback.  Three sites in this file (the protoc
# `-I` flag plus the google/protobuf/*.proto source paths around line
# 750) still reference the uppercase form, so set it explicitly here so
# the build is portable across cmake versions.
if(NOT DEFINED PROTOBUF_INCLUDE_DIR OR "${PROTOBUF_INCLUDE_DIR}" STREQUAL "")
    set(PROTOBUF_INCLUDE_DIR ${Protobuf_INCLUDE_DIR})
endif()

# protobuf-c
# Mirror the protobuf block above: inside a conda env, resolve protobuf-c
# strictly from the env (NO_DEFAULT_PATH) so we don't latch onto a system
# libprotobuf-c.so whose dev symlink may be absent on the host (which leaves
# a dangling DEPENDS path -> "No rule to make target .../libprotobuf-c.so").
set(_at_pbc_resolved FALSE)
if(DEFINED ENV{CONDA_PREFIX})
    find_path(_at_pbc_inc protobuf-c.h PATH_SUFFIXES protobuf-c
              HINTS ${CONDA_ROOT} NO_DEFAULT_PATH)
    find_library(_at_pbc_lib NAMES protobuf-c HINTS ${CONDA_ROOT} NO_DEFAULT_PATH)
    if(_at_pbc_inc AND _at_pbc_lib)
        set(LIBPROTOBUF_C_INCLUDE_DIR ${_at_pbc_inc} CACHE PATH "" FORCE)
        set(LIBPROTOBUF_C_LIBRARY ${_at_pbc_lib} CACHE FILEPATH "" FORCE)
        set(_at_pbc_resolved TRUE)
    endif()
endif()
if(NOT _at_pbc_resolved)
    find_path(LIBPROTOBUF_C_INCLUDE_DIR protobuf-c.h PATH_SUFFIXES protobuf-c)
    find_library(LIBPROTOBUF_C_LIBRARY NAMES protobuf-c)
endif()
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
    autonomous_trust/network/net_transport_ip.c
    autonomous_trust/network/net_transport_udp.c
    autonomous_trust/network/net_transport_tcp.c
    autonomous_trust/network/net_transport_hybrid.c
    autonomous_trust/network/net_transport_registry.c
    autonomous_trust/network/network.c
    autonomous_trust/bootstrap/bootstrap_capabilities.c
    autonomous_trust/bootstrap/bootstrap_worker.c
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
    autonomous_trust/utilities/at_jansson.c
    autonomous_trust/utilities/b64.c
    autonomous_trust/utilities/err_str.c
    autonomous_trust/utilities/exception.c
    autonomous_trust/utilities/logger.c
    autonomous_trust/utilities/message.c
    autonomous_trust/utilities/msg_types.c
    autonomous_trust/utilities/probes.c
    autonomous_trust/utilities/protobuf_shutdown.cpp
    autonomous_trust/utilities/queue_pool.c
    autonomous_trust/utilities/sighandler.c
    autonomous_trust/utilities/socket_helpers.c
    autonomous_trust/utilities/timeout.c
    autonomous_trust/utilities/util.c
    autonomous_trust/fleet/update_proposal.c
    autonomous_trust/fleet/fleet_helpers.c
    autonomous_trust/fleet/fleet_ops.c
    autonomous_trust/data_source/data_source_proc.c
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

# DTN sources (only compiled when AT_NET_DTN is enabled). Files live in
# a `dtn/` subdirectory so the process-table preprocessor can exclude them
# cleanly when AT_NET_DTN is off (see `_exclude_args` in preprocess()).
if(AT_NET_DTN)
    list(APPEND libsrc
        autonomous_trust/network/dtn/dtn_eid.c
        autonomous_trust/network/dtn/net_transport_dtn.c
    )
    if(AT_NET_DTN_BACKEND STREQUAL "stub")
        list(APPEND libsrc autonomous_trust/network/dtn/dtn_backend_stub.c)
    elseif(AT_NET_DTN_BACKEND STREQUAL "ion")
        # NASA ION bp_* API. Two modes:
        #   (a) Submodule present at ./third_party/ION-DTN — we build it
        #       via autotools into a build-local prefix. No sudo required.
        #   (b) Submodule absent — fall back to system-installed ION (or
        #       paths supplied explicitly via -DION_* cache vars).
        # The node's local EID must be pre-provisioned via bpadmin before
        # the transport is used at runtime.
        set(ION_SUBMODULE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ION-DTN)
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
            # Pre-create the include dir so include_directories() below has
            # something to add even before the first build runs.
            file(MAKE_DIRECTORY ${ION_PREFIX}/include)
            set(ION_INCLUDE_DIR ${ION_PREFIX}/include)
            set(ION_BP_LIB  ${ION_PREFIX}/lib/libbp${CMAKE_SHARED_LIBRARY_SUFFIX})
            set(ION_ICI_LIB ${ION_PREFIX}/lib/libici${CMAKE_SHARED_LIBRARY_SUFFIX})
            set(ION_EXTERNAL_TARGET ion_external)
            # Propagate RPATH so AT executables can find the in-build ION
            # shared libs at runtime without LD_LIBRARY_PATH.
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
            set(ION_EXTERNAL_TARGET "")
        endif()

        list(APPEND libsrc autonomous_trust/network/dtn/dtn_backend_ion.c)
        include_directories(${ION_INCLUDE_DIR})
        list(APPEND DEPENDENCIES      ${ION_BP_LIB} ${ION_ICI_LIB})
        list(APPEND TEST_DEPENDENCIES ${ION_BP_LIB} ${ION_ICI_LIB})
    elseif(AT_NET_DTN_BACKEND STREQUAL "ud3tn")
        # uD3TN legacy AAP v1 binary protocol over Unix-socket or TCP — no
        # external library needed; the daemon must be reachable at runtime via
        # AT_DTN_UD3TN_SOCKET (e.g. "unix:./ud3tn.aap.socket" or "tcp:host:port").
        list(APPEND libsrc autonomous_trust/network/dtn/dtn_backend_ud3tn.c)
    elseif(AT_NET_DTN_BACKEND STREQUAL "ud3tnv2")
        # uD3TN AAP 2.0: protobuf-delimited framing. Schema lives at
        # autonomous_trust/network/dtn/proto/aap2.proto, vendored verbatim
        # from https://gitlab.com/d3tn/ud3tn/-/raw/master/components/aap2/aap2.proto
        # Currently symlinked to submodule location in ./third_party/ud3tn/
        #
        # Codegen is a standalone protoc-c run — we don't reuse the main
        # `protos` list because aap2.proto lives under the DTN tree, not the
        # AT protobuf/ root. Generated sources land in the build tree.
        set(AAP2_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/autonomous_trust/network/dtn/proto)
        set(AAP2_GEN_DIR   ${CMAKE_CURRENT_BINARY_DIR}/autonomous_trust/network/dtn/proto)
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
        list(APPEND libsrc
            autonomous_trust/network/dtn/dtn_backend_ud3tnv2.c
            ${AAP2_GEN_DIR}/aap2.pb-c.c
        )
        include_directories(${AAP2_GEN_DIR})
    else()
        message(FATAL_ERROR "Unknown AT_NET_DTN_BACKEND: ${AT_NET_DTN_BACKEND}")
    endif()
    add_compile_definitions(AT_NET_DTN)
endif()

# Forwarding envelope (see at-over-dtn.md §4.3). Codec only — consumers of
# the header are wired in net_proc.c in slice 2b.2.
if(AT_NET_ENVELOPE)
    list(APPEND libsrc autonomous_trust/network/net_envelope.c)
    add_compile_definitions(AT_NET_ENVELOPE)
endif()

if(AT_NET_GROUP_FORWARD)
    add_compile_definitions(AT_NET_GROUP_FORWARD)
endif()

if(AT_DISCOVERY_CROSS_CLUSTER)
    add_compile_definitions(AT_DISCOVERY_CROSS_CLUSTER)
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
    autonomous_trust/network/net_transport.h
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
    if(NOT AT_NET_DTN)
        list(APPEND _exclude_args --exclude dtn)
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

# Ryu (shortest-decimal d2s) for JCS number formatting.  Pulled in as a
# git submodule under third_party/ryu/; the upstream repo's C sources live
# in its `ryu/` subdir, so source paths read `third_party/ryu/ryu/...`.
# Includes go via `ryu/ryu.h` — the include-dir at `third_party/ryu/`
# lets that resolve to `third_party/ryu/ryu/ryu.h`.
#
# Build target defined here at top level so both the conformance runner
# and the jcs_test target can link against it.
add_library(at_ryu STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ryu/ryu/d2s.c
)
target_include_directories(at_ryu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ryu
)
# Ryu emits a few unused-variable warnings on some compilers; suppress
# rather than patch the submodule.
target_compile_options(at_ryu PRIVATE -O2 -Wno-error -Wno-unused-function)

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

# If ION is being built from the in-tree submodule, force the ExternalProject
# to complete (install libs + headers) before either AT library starts
# compiling — otherwise dtn_backend_ion.c would fail on #include <bp.h>.
if(DEFINED ION_EXTERNAL_TARGET AND ION_EXTERNAL_TARGET)
    add_dependencies(autonomous_trust        ${ION_EXTERNAL_TARGET})
    add_dependencies(autonomous_trust_static ${ION_EXTERNAL_TARGET})
endif()


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

add_executable(bootstrap_capabilities_test test/bootstrap_capabilities_test.c)
set_source_files_properties(test/bootstrap_capabilities_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(bootstrap_capabilities_test PRIVATE ${AT_TEST_LIBS})

add_executable(bootstrap_worker_test test/bootstrap_worker_test.c)
set_source_files_properties(test/bootstrap_worker_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(bootstrap_worker_test PRIVATE ${AT_TEST_LIBS})

add_executable(net_message_test test/net_message_test.c)
set_source_files_properties(test/net_message_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(net_message_test PRIVATE ${AT_TEST_LIBS})

add_executable(socket_helpers_test test/socket_helpers_test.c)
set_source_files_properties(test/socket_helpers_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(socket_helpers_test PRIVATE ${AT_TEST_LIBS} pthread)

add_executable(at_jansson_test test/at_jansson_test.c)
set_source_files_properties(test/at_jansson_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(at_jansson_test PRIVATE ${AT_TEST_LIBS})

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

add_executable(partition_recovery_test test/partition_recovery_test.c)
set_source_files_properties(test/partition_recovery_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(partition_recovery_test PRIVATE ${AT_TEST_LIBS})

add_executable(late_joiner_caps_resync_test test/late_joiner_caps_resync_test.c)
set_source_files_properties(test/late_joiner_caps_resync_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(late_joiner_caps_resync_test PRIVATE ${AT_TEST_LIBS})

add_executable(identity_resync_test test/identity_resync_test.c)
set_source_files_properties(test/identity_resync_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(identity_resync_test PRIVATE ${AT_TEST_LIBS})

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

# Cross-language parity test for the C JCS canonicalizer.  Pulls in
# conformance/jcs.c directly so the test is independent of whether the
# conformance harness build is enabled.  Doesn't need the full AT static
# archive — only jansson, Ryu, libcheck (+ subunit when libcheck is
# statically linked) and libm for isnan/isinf.
add_executable(jcs_test
    test/jcs_test.c
    conformance/jcs.c
)
set_source_files_properties(test/jcs_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(jcs_test PRIVATE
    at_ryu
    ${LIBJANSSON_LIBRARY}
    ${LIBCHECK_LIBRARY}
    subunit
    m
    pthread
    rt
)

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
add_test(NAME bootstrap_capabilities_test COMMAND $<TARGET_FILE:bootstrap_capabilities_test>)
add_test(NAME bootstrap_worker_test COMMAND $<TARGET_FILE:bootstrap_worker_test>)
add_test(NAME net_message_test COMMAND $<TARGET_FILE:net_message_test>)
add_test(NAME socket_helpers_test COMMAND $<TARGET_FILE:socket_helpers_test>)
add_test(NAME at_jansson_test COMMAND $<TARGET_FILE:at_jansson_test>)
add_test(NAME negotiation_test COMMAND $<TARGET_FILE:negotiation_test>)
add_test(NAME reputation_test COMMAND $<TARGET_FILE:reputation_test>)
add_test(NAME history_test COMMAND $<TARGET_FILE:history_test>)
add_test(NAME queue_pool_test COMMAND $<TARGET_FILE:queue_pool_test>)
add_test(NAME network_test COMMAND $<TARGET_FILE:network_test>)
add_test(NAME identity_test COMMAND $<TARGET_FILE:identity_test>)
add_test(NAME partition_recovery_test COMMAND $<TARGET_FILE:partition_recovery_test>)
add_test(NAME late_joiner_caps_resync_test COMMAND $<TARGET_FILE:late_joiner_caps_resync_test>)
add_test(NAME identity_resync_test COMMAND $<TARGET_FILE:identity_resync_test>)
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
add_test(NAME jcs_test COMMAND $<TARGET_FILE:jcs_test>)

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
    autonomous_trust/utilities/at_jansson.c
    ${fleet_test_util_srcs})
set_source_files_properties(test/update_proc_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(update_proc_test PRIVATE ${TEST_DEPENDENCIES})
add_dependencies(update_proc_test autonomous_trust_static)

add_test(NAME update_proc_test COMMAND $<TARGET_FILE:update_proc_test>)

add_executable(config_proc_test
    test/config_proc_test.c
    autonomous_trust/fleet/config_proc_helpers.c
    autonomous_trust/fleet/update_proc_helpers.c
    autonomous_trust/utilities/at_jansson.c
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

# Hybrid-transport routing unit tests — always compiled; no backend needed,
# this is a pure-math test of the matcher logic.
add_executable(hybrid_route_test test/hybrid_route_test.c)
set_source_files_properties(test/hybrid_route_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(hybrid_route_test PRIVATE ${AT_TEST_LIBS})
add_test(NAME hybrid_route_test COMMAND $<TARGET_FILE:hybrid_route_test>)

# IPv6 CIDR matching — split into its own binary to stay under the
# RUN_TESTS 9-arg cap in test_setup.h.
add_executable(hybrid_route6_test test/hybrid_route6_test.c)
set_source_files_properties(test/hybrid_route6_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(hybrid_route6_test PRIVATE ${AT_TEST_LIBS})
add_test(NAME hybrid_route6_test COMMAND $<TARGET_FILE:hybrid_route6_test>)

# Timeout-scaling tests — the pure-arithmetic kernel of the
# timeout-adaptation layer (utilities/timeout.h).
add_executable(timeout_scale_test test/timeout_scale_test.c)
set_source_files_properties(test/timeout_scale_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(timeout_scale_test PRIVATE ${AT_TEST_LIBS})
add_test(NAME timeout_scale_test COMMAND $<TARGET_FILE:timeout_scale_test>)

# PEER_RTT_UPDATE propagation (at-over-dtn §4.3 B-followup).
# Drives run_message_handlers with a PEER_RTT_UPDATE and asserts the
# target peer's peer_rtt_ms[] slot changes.
add_executable(peer_rtt_update_test test/peer_rtt_update_test.c)
set_source_files_properties(test/peer_rtt_update_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(peer_rtt_update_test PRIVATE ${AT_TEST_LIBS})
add_test(NAME peer_rtt_update_test COMMAND $<TARGET_FILE:peer_rtt_update_test>)

# Envelope codec unit tests — gated by AT_NET_ENVELOPE since the codec TU
# itself is only compiled when that option is ON.
if(AT_NET_ENVELOPE)
    add_executable(net_envelope_test test/net_envelope_test.c)
    set_source_files_properties(test/net_envelope_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(net_envelope_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME net_envelope_test COMMAND $<TARGET_FILE:net_envelope_test>)

    # Multi-hop relay test — exercises the envelope forwarding protocol
    # end-to-end across simulated A -> G [-> G2] -> B paths without
    # bringing up real transports or threads.
    add_executable(envelope_relay_test test/envelope_relay_test.c)
    set_source_files_properties(test/envelope_relay_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(envelope_relay_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME envelope_relay_test COMMAND $<TARGET_FILE:envelope_relay_test>)

    # Cross-leg broadcast forwarding gate + dedup fingerprint. Split from
    # envelope_relay_test to stay under the 9-test RUN_TESTS cap.
    add_executable(envelope_bcast_test test/envelope_bcast_test.c)
    set_source_files_properties(test/envelope_bcast_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(envelope_bcast_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME envelope_bcast_test COMMAND $<TARGET_FILE:envelope_bcast_test>)

    # Integration-ish test: drives the real net_proc handle_inbound_peer()
    # through a mock transport, asserting forward/drop/local behavior
    # end-to-end without bringing up daemonize()'d processes or sockets.
    add_executable(net_proc_relay_test test/net_proc_relay_test.c)
    set_source_files_properties(test/net_proc_relay_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(net_proc_relay_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME net_proc_relay_test COMMAND $<TARGET_FILE:net_proc_relay_test>)

    # Deferred-message uuid-keyed retry (stage G). Verifies that under
    # envelope mode the deferred-message ring keys by envelope src_uuid,
    # not the gateway's transport from_addr.
    add_executable(net_proc_defer_test test/net_proc_defer_test.c)
    set_source_files_properties(test/net_proc_defer_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(net_proc_defer_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME net_proc_defer_test COMMAND $<TARGET_FILE:net_proc_defer_test>)

    # Cross-group forward path (stage F) — gated on AT_NET_GROUP_FORWARD
    # because it drives the code in handle_inbound_group that only exists
    # under that option. Envelope is still needed for envelope pack/unpack.
    if(AT_NET_GROUP_FORWARD)
        add_executable(envelope_group_forward_test test/envelope_group_forward_test.c)
        set_source_files_properties(test/envelope_group_forward_test.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_link_libraries(envelope_group_forward_test PRIVATE ${AT_TEST_LIBS})
        add_test(NAME envelope_group_forward_test COMMAND $<TARGET_FILE:envelope_group_forward_test>)
    endif()

    # Cross-cluster peer discovery (stage E) — verifies that forwarded
    # ID_ANNOUNCE broadcasts preserve the announcer's self-reported
    # address (so replies route back through the gateway).
    if(AT_DISCOVERY_CROSS_CLUSTER)
        add_executable(discovery_cross_cluster_test test/discovery_cross_cluster_test.c)
        set_source_files_properties(test/discovery_cross_cluster_test.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_link_libraries(discovery_cross_cluster_test PRIVATE ${AT_TEST_LIBS})
        add_test(NAME discovery_cross_cluster_test COMMAND $<TARGET_FILE:discovery_cross_cluster_test>)
    endif()

    # Per-leg broadcast exclusion (stage D-followup). Verifies
    # handle_inbound_broadcast uses send_broadcast_except_leg when the
    # transport reports a known last_recv_leg, and falls back to
    # send_broadcast otherwise. Compiled whenever envelope mode is on —
    # the refinement is zero-cost when irrelevant, so no separate option.
    add_executable(broadcast_except_leg_test test/broadcast_except_leg_test.c)
    set_source_files_properties(test/broadcast_except_leg_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(broadcast_except_leg_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME broadcast_except_leg_test COMMAND $<TARGET_FILE:broadcast_except_leg_test>)
endif()

# DTN tests (only when AT_NET_DTN is enabled). dtn_eid_test is pure string
# math so it runs against any backend. dtn_transport_test exercises the
# transport's send/recv paths through the backend vtable; it assumes the
# no-op stub (send returns 0, recv returns ENOMSG) and would misbehave
# against a real daemon, so it is gated to the stub backend only.
if(AT_NET_DTN)
    add_executable(dtn_eid_test test/dtn_eid_test.c)
    set_source_files_properties(test/dtn_eid_test.c PROPERTIES COMPILE_FLAGS "-Wall")
    target_link_libraries(dtn_eid_test PRIVATE ${AT_TEST_LIBS})
    add_test(NAME dtn_eid_test COMMAND $<TARGET_FILE:dtn_eid_test>)

    if(AT_NET_DTN_BACKEND STREQUAL "stub")
        add_executable(dtn_transport_test test/dtn_transport_test.c)
        set_source_files_properties(test/dtn_transport_test.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_link_libraries(dtn_transport_test PRIVATE ${AT_TEST_LIBS})
        add_test(NAME dtn_transport_test COMMAND $<TARGET_FILE:dtn_transport_test>)
    endif()
endif()

endif() # LIBCHECK_LIBRARY

####################
# Conformance harness (cross-language test corpus runner)
#
# Reads JSON-mirrored corpus produced from src/autonomous-trust/conformance/
# at build time, runs each case through C-side adapters, emits a results
# JSON whose shape matches the Python harness output. Optional — only
# wired when the autonomous-trust Python sources are present alongside.
if(EXISTS ${CMAKE_SOURCE_DIR}/../autonomous-trust/conformance)
    add_subdirectory(conformance)
endif()

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

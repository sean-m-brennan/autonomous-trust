# CMake toolchain file for cross-compiling the C core to SPARC V8 / LEON3.
#
# Uses the Buildroot output built from leon3_defconfig. Point AT_SPARC_BR_OUT
# at it (default /var/tmp/at-sparc-leon3), either as -DAT_SPARC_BR_OUT=... or
# in the environment. The target libraries come from Buildroot's staging
# sysroot; protoc and protoc-c come from its host tree, so the generated
# .pb-c.c matches the libprotobuf-c it links against. See
# embedded/test-conformance-sparc.sh.

if(NOT AT_SPARC_BR_OUT)
    if(DEFINED ENV{AT_SPARC_BR_OUT})
        set(AT_SPARC_BR_OUT $ENV{AT_SPARC_BR_OUT})
    else()
        set(AT_SPARC_BR_OUT /var/tmp/at-sparc-leon3)
    endif()
endif()
# try_compile projects re-read this file without the cache, so hand it down
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES AT_SPARC_BR_OUT)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR sparc)

set(_br_host ${AT_SPARC_BR_OUT}/host)
set(CMAKE_SYSROOT ${_br_host}/sparc-buildroot-linux-uclibc/sysroot)
set(CMAKE_C_COMPILER ${_br_host}/bin/sparc-linux-gcc)
set(CMAKE_CXX_COMPILER ${_br_host}/bin/sparc-linux-g++)

set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# The build only runs protoc; it never links libprotobuf. FindProtobuf still
# insists on a library, so give it the host one, which nothing links.
set(Protobuf_PROTOC_EXECUTABLE ${_br_host}/bin/protoc CACHE FILEPATH "")
set(Protobuf_INCLUDE_DIR ${_br_host}/include CACHE PATH "")
set(Protobuf_LIBRARY ${_br_host}/lib/libprotobuf.so CACHE FILEPATH "")

# Targets the build runs (conformance_c) go through user-mode QEMU.
find_program(_at_qemu_sparc qemu-sparc)
if(_at_qemu_sparc)
    set(CMAKE_CROSSCOMPILING_EMULATOR ${_at_qemu_sparc} -L ${CMAKE_SYSROOT})
endif()

# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Top-level build for AutonomousTrust example applications.
#
# Builds the library (if not already built) and then each example.
#
# Usage (from examples/):
#   mkdir build && cd build
#   cmake .. [-DAT_ZTA=ON]
#   make -j$(nproc)
#
# Or from the repo root:
#   cmake -S examples -B examples/build [-DAT_ZTA=ON]
#   cmake --build examples/build

cmake_minimum_required(VERSION 3.23)
project(autonomous_trust_examples C CXX)

# Forward key options to the library build
option(AT_ZTA "Enable Zero Trust Architecture credential integration" OFF)
option(AT_STATIC "Link demos fully statically" OFF)

# OpenSSL imported targets must be visible in this scope for linking
if(AT_ZTA)
    find_package(OpenSSL REQUIRED)
endif()

# Build the library as a subdirectory.
# This makes autonomous_trust_static (and its include dirs, compile defs,
# dependencies) available to all example targets without installing first.
set(AT_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src/c")
add_subdirectory("${AT_LIB_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/lib")

# Gather the library's dependencies so example targets can link them.
# These are set in src/c/CMakeLists.txt and visible here because
# add_subdirectory runs in the same scope chain.
# If DEPENDENCIES is not set (shouldn't happen), fall back to a minimal set.
if(NOT DEPENDENCIES)
    message(WARNING "DEPENDENCIES not inherited from library build — linking may fail")
endif()

# Include directories that the library exposes to consumers.
# The library uses include_directories() (directory-scoped) so we must
# replicate them for targets outside that directory.
set(AT_INCLUDE_DIRS
    ${AT_LIB_DIR}
    ${AT_LIB_DIR}/autonomous_trust
    ${CMAKE_CURRENT_BINARY_DIR}/lib                  # generated headers
    ${CMAKE_CURRENT_BINARY_DIR}/lib/autonomous_trust  # generated headers
    ${CMAKE_CURRENT_BINARY_DIR}/lib/protobuf
    ${CMAKE_CURRENT_BINARY_DIR}/lib/protobuf/autonomous_trust/core/protobuf
)

# Helper function: build an example app against the static library.
function(add_at_example target source)
    add_executable(${target} ${source})
    target_include_directories(${target} PRIVATE ${AT_INCLUDE_DIRS})
    target_link_libraries(${target} PRIVATE
        -Wl,--whole-archive autonomous_trust_static -Wl,--no-whole-archive
        ${DEPENDENCIES}
    )
    # -fms-extensions is REQUIRED, not cosmetic: the library headers embed
    # smrt_ptr_t (and struct tm / thread_args_t / public_identity_t) as
    # anonymous typedef'd members. Without this flag GCC silently drops those
    # members ("declaration does not declare anything"), giving the example a
    # struct layout that disagrees with the library it links against. The
    # library itself is built with -fms-extensions (src/c/CMakeLists.txt:136).
    target_compile_options(${target} PRIVATE -Wall -fms-extensions)
    # clang still emits -Wmicrosoft-anon-tag for those deliberate anonymous
    # typedef'd members even with -fms-extensions; the library build suppresses
    # the same spurious warning (src/c/CMakeLists.txt:125).
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE -Wno-microsoft-anon-tag)
    endif()
    install(TARGETS ${target} RUNTIME DESTINATION bin)
endfunction()

# ----- Minimal host app (src/c/example.c) -----
# Built here because nothing built it before: it is the reference an integrator
# copies, and an uncompiled reference is one nothing checks. It shipped with
# app_name != q_in, so the daemon's messages went to a socket the app had not
# bound and the tick callback could never have received anything.
add_at_example(at_example ../src/c/example.c)

# ----- Demo app (fleet update, containerized) -----
add_at_example(at_demo demo/src/at_demo.c)
if(AT_STATIC)
    target_link_libraries(at_demo PRIVATE -static stdc++ m)
endif()

# ----- ZTA demo app (DDIL, OCSP, delegated verification) -----
if(AT_ZTA)
    add_at_example(at_zta_demo zta/src/at_zta_demo.c)
endif()

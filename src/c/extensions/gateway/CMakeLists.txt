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

# libat_gateway: the gateway relay (routing envelope, broadcast relay,
# cross-leg group forward, cross-cluster discovery) as an extension library
# (FEATURE_SPLIT_PLAN Phase 2; see doc/architecture/extensions.md). Reached
# from the core CMakeLists.txt with add_subdirectory when AT_NET_GATEWAY is
# ON, after the core targets and AT_TEST_LIBS exist, so the core's include
# dirs, compile flags and dependency lists are inherited here.
#
# The library registers the "gateway" extension from a constructor
# (gateway.c). That installs the "envelope" network filter only when a
# node's network config sets "envelope": true, so linking or loading it
# changes nothing on its own. It includes the core's private headers
# (net_proc_priv.h, process_t) and must be built by this same project with
# the same flags.
#
#   at_gateway         SHARED, linked against libautonomous_trust.so
#   at_gateway_static  STATIC (libat_gateway.a), for static consumers, which
#                      link it with --whole-archive or call at_gateway_link()

set(AT_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(at_gateway_src
    net_envelope.c
    gateway.c
)

add_library(at_gateway SHARED ${at_gateway_src})
# Link the core .so by file, not by target: the core's target_sources(...
# PUBLIC ${libsrc}) would otherwise compile a second copy of the whole core
# into libat_gateway, with its own process tables and filter chain.
target_link_libraries(at_gateway PRIVATE $<TARGET_LINKER_FILE:autonomous_trust>)
add_dependencies(at_gateway autonomous_trust)

add_library(at_gateway_static STATIC ${at_gateway_src})
set_target_properties(at_gateway_static PROPERTIES OUTPUT_NAME at_gateway)
# Static: nothing links the core in, but its generated headers must exist.
add_dependencies(at_gateway_static autonomous_trust_static)

foreach(_t at_gateway at_gateway_static)
    set_target_properties(${_t} PROPERTIES COMPILE_FLAGS "${lib_compile_flags}")
    target_include_directories(${_t} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

install(TARGETS at_gateway at_gateway_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

####################
# tests (only built when libcheck is available)
#
# A test links the extension whole, then the core group, so the gateway's
# registration constructor is in the binary and resolves against the core.
# The net_proc-driving tests set "envelope" (and group_forward /
# cross_cluster where they need them) on their network_config_t and install
# the filter through the extension (test/gateway_test.h), as a node would.
if(LIBCHECK_LIBRARY)
    set(AT_GATEWAY_TEST_LIBS
        -Wl,--whole-archive at_gateway_static -Wl,--no-whole-archive
        ${AT_TEST_LIBS})

    function(add_gateway_test name)
        add_executable(${name} test/${name}.c)
        set_source_files_properties(test/${name}.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_include_directories(${name} PRIVATE ${AT_C_DIR}/test ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${name} PRIVATE ${AT_GATEWAY_TEST_LIBS})
        add_test(NAME ${name} COMMAND $<TARGET_FILE:${name}>)
    endfunction()

    # Codec: pack/unpack, disposition, forward gates, fingerprints.
    add_gateway_test(net_envelope_test)
    # Multi-hop relay across simulated A -> G [-> G2] -> B paths.
    add_gateway_test(envelope_relay_test)
    # Cross-leg broadcast forwarding gate + dedup fingerprint.
    add_gateway_test(envelope_bcast_test)
    # The real handle_inbound_peer/_broadcast through a mock transport:
    # forward / drop / local, and broadcast relay with dedup.
    add_gateway_test(net_proc_relay_test)
    # The deferred-message ring keys by envelope src_uuid (stage G).
    add_gateway_test(net_proc_defer_test)
    # Cross-group forward on a configured leg (stage F; group_forward).
    add_gateway_test(envelope_group_forward_test)
    # Forwarded ID_ANNOUNCE keeps the self-reported address (stage E;
    # cross_cluster).
    add_gateway_test(discovery_cross_cluster_test)
    # Broadcast relay skips the leg it arrived on (D-followup).
    add_gateway_test(broadcast_except_leg_test)
    # Linking registers the extension; the filter goes in only on config.
    add_gateway_test(gateway_link_test)
endif()

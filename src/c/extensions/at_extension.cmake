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

# Shared shape of an extension library (src/c/extensions/<name>/), for the
# ones that need no more than it: the five oracle layers (FEATURE_SPLIT_PLAN
# Phase 3). dtn and gateway predate it and spell the same shape out.
# Included from the core CMakeLists.txt after the core targets and
# AT_TEST_LIBS exist, so core include dirs, flags and dependencies apply.
#
#   at_<name>         SHARED, linked against libautonomous_trust.so BY FILE:
#                     the core's target_sources(... PUBLIC ${libsrc}) would
#                     otherwise compile a second copy of the whole core into
#                     it, with its own registries.
#   at_<name>_static  STATIC (libat_<name>.a), for static consumers, which
#                     link it with --whole-archive or call at_<name>_link().
#
# Both export src/c/extensions as a PUBLIC include dir, so a header is
# included as "<name>/<header>.h" -- the spelling it had in the core.

set(AT_EXT_DIR ${CMAKE_CURRENT_LIST_DIR})

# at_extension_library(<name> SOURCES <src>... [DEPENDS <extension>...])
function(at_extension_library name)
    cmake_parse_arguments(A "" "" "SOURCES;DEPENDS" ${ARGN})
    add_library(at_${name} SHARED ${A_SOURCES})
    target_link_libraries(at_${name} PRIVATE $<TARGET_LINKER_FILE:autonomous_trust>)
    add_dependencies(at_${name} autonomous_trust)

    add_library(at_${name}_static STATIC ${A_SOURCES})
    set_target_properties(at_${name}_static PROPERTIES OUTPUT_NAME at_${name})
    # Static: nothing links the core in, but its generated headers must exist.
    add_dependencies(at_${name}_static autonomous_trust_static)

    foreach(_d ${A_DEPENDS})
        target_link_libraries(at_${name} PRIVATE at_${_d})
        add_dependencies(at_${name}_static at_${_d}_static)
    endforeach()
    # The include root is the extension directory's parent, so "<name>/x.h"
    # resolves for an in-tree extension (AT_EXT_DIR) and an external one alike.
    get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
    foreach(_t at_${name} at_${name}_static)
        set_target_properties(${_t} PROPERTIES COMPILE_FLAGS "${lib_compile_flags}")
        target_include_directories(${_t} PUBLIC ${AT_EXT_DIR} ${_root})
    endforeach()
    set_property(TARGET at_${name}_static PROPERTY AT_EXT_DEPENDS "${A_DEPENDS}")

    install(TARGETS at_${name} at_${name}_static
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
endfunction()

# at_extension_tests(<name> <test>...): test/<test>.c, linked with the
# extension (and the extensions it depends on) whole, then the core group, so
# the registration constructors are in the binary and resolve against the core.
function(at_extension_tests name)
    if(NOT LIBCHECK_LIBRARY)
        return()
    endif()
    get_property(_deps TARGET at_${name}_static PROPERTY AT_EXT_DEPENDS)
    set(_whole at_${name}_static)
    foreach(_d ${_deps})
        list(APPEND _whole at_${_d}_static)
    endforeach()
    get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
    foreach(_t ${ARGN})
        add_executable(${_t} test/${_t}.c)
        set_source_files_properties(test/${_t}.c PROPERTIES COMPILE_FLAGS "-Wall")
        target_include_directories(${_t} PRIVATE ${AT_EXT_DIR}/../test ${AT_EXT_DIR} ${_root})
        # libsubunit when found: a static libcheck needs it as soon as a test
        # pulls in its logging (empty and skipped otherwise; see LIBSUBUNIT_LIBRARY).
        target_link_libraries(${_t} PRIVATE
            -Wl,--whole-archive ${_whole} -Wl,--no-whole-archive ${AT_TEST_LIBS}
            ${LIBSUBUNIT_LIBRARY})
        add_test(NAME ${_t} COMMAND $<TARGET_FILE:${_t}>)
    endforeach()
endfunction()

# A conformance adapter for a protocol this extension owns (doc/architecture/
# extensions.md, "External extensions"). Recorded here and read by
# conformance/CMakeLists.txt, which is added after every extension:
#   PROTOCOL  the corpus `protocol:` name the adapter runs
#   RUN       its entry point, void RUN(const at_case_t *, at_case_result_t *)
#   SOURCES   the adapter's C sources (relative to the calling directory)
#   LIBS      libraries linked whole into the runner (e.g. at_<name>_static)
#   CORPUS    a corpus root holding scenarios/<protocol>/*.yaml, mirrored with
#             AT's own
function(at_conformance_adapter)
    cmake_parse_arguments(A "" "PROTOCOL;RUN;CORPUS" "SOURCES;LIBS" ${ARGN})
    if(NOT A_PROTOCOL OR NOT A_RUN)
        message(FATAL_ERROR "at_conformance_adapter: PROTOCOL and RUN are required")
    endif()
    set(_srcs)
    foreach(_s ${A_SOURCES})
        get_filename_component(_s "${_s}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
        list(APPEND _srcs "${_s}")
    endforeach()
    get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
    set_property(GLOBAL APPEND PROPERTY AT_CONF_EXT_ADAPTERS "${A_PROTOCOL}=${A_RUN}")
    set_property(GLOBAL APPEND PROPERTY AT_CONF_EXT_SOURCES ${_srcs})
    set_property(GLOBAL APPEND PROPERTY AT_CONF_EXT_LIBS ${A_LIBS})
    set_property(GLOBAL APPEND PROPERTY AT_CONF_EXT_INCLUDES "${_root}")
    if(A_CORPUS)
        get_filename_component(_c "${A_CORPUS}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
        set_property(GLOBAL APPEND PROPERTY AT_CONF_EXT_CORPORA "${_c}")
    endif()
endfunction()

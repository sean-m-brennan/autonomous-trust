# ******************
#  Copyright 2026 Sean M. Brennan and contributors
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

# AutonomousTrust C-side conformance harness.
#
# Reads the JSON-mirrored corpus produced at build time by the Python
# preprocessor (`tools/corpus_to_json.py`), runs each case through a
# protocol-specific adapter, and emits a results JSON whose shape matches
# the Python harness's so the cross-language diff tool can compare them.

# Source paths
set(AT_CONFORMANCE_SOURCES
    runner.c
    scenario_loader.c
    scenario_engine.c
    case_result.c
    negative_runner.c
    adapters/network.c
    adapters/identity.c
    adapters/agreement.c
    adapters/negotiation.c
    adapters/reputation.c
)

# The corpus YAML lives next to src/c/, under src/autonomous-trust/conformance/.
# CMake needs an absolute path to drive the YAML→JSON conversion via Python.
set(AT_CONFORMANCE_CORPUS_YAML
    ${CMAKE_SOURCE_DIR}/../autonomous-trust/conformance
    CACHE PATH "Path to the YAML conformance corpus root")

set(AT_CONFORMANCE_CORPUS_JSON
    ${CMAKE_BINARY_DIR}/conformance/corpus-json
    CACHE PATH "Build-time output dir for JSON-mirrored corpus")

set(AT_CONFORMANCE_RESULTS
    ${CMAKE_BINARY_DIR}/conformance/results
    CACHE PATH "Where conformance_c writes its results JSON")

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# Custom command: run the YAML→JSON converter. Inputs are every YAML file
# under the corpus; output is the index.json (ninja/make rebuild key).
file(GLOB_RECURSE AT_CONFORMANCE_YAML_FILES
    CONFIGURE_DEPENDS
    ${AT_CONFORMANCE_CORPUS_YAML}/scenarios/*.yaml
    ${AT_CONFORMANCE_CORPUS_YAML}/vectors/*.yaml
)

add_custom_command(
    OUTPUT ${AT_CONFORMANCE_CORPUS_JSON}/index.json
    COMMAND ${CMAKE_COMMAND} -E env
            "PYTHONPATH=${CMAKE_SOURCE_DIR}/../autonomous-trust"
            ${Python3_EXECUTABLE} -m tools.corpus_to_json
            --in ${AT_CONFORMANCE_CORPUS_YAML}
            --out ${AT_CONFORMANCE_CORPUS_JSON}
    DEPENDS ${AT_CONFORMANCE_YAML_FILES}
            ${CMAKE_SOURCE_DIR}/../autonomous-trust/tools/corpus_to_json.py
            ${CMAKE_SOURCE_DIR}/../autonomous-trust/conformance/harness/common/scenario_loader.py
    COMMENT "Converting YAML corpus -> JSON for C harness"
    VERBATIM
)

add_custom_target(at_conformance_json
    DEPENDS ${AT_CONFORMANCE_CORPUS_JSON}/index.json
)

# The runner executable. Linked against the existing static lib to pick up
# any future C-side wire/scenario adapters that need framework symbols.
add_executable(conformance_runner ${AT_CONFORMANCE_SOURCES})
add_dependencies(conformance_runner at_conformance_json)

target_include_directories(conformance_runner
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/autonomous_trust
)

# Mirror the test executables' link line: --start-group/--end-group around
# the static archive lets the linker make multiple resolution passes, which
# is necessary because msg_types.c (and the protobuf-c generated objects)
# pull in symbols defined later in the archive's link order. Without this,
# protobuf_c_message_* symbols come up undefined even though they're in
# libprotobuf-c, because libsymbols are resolved single-pass.
set(AT_CONFORMANCE_LIBS
    -Wl,--start-group autonomous_trust_static ${TEST_DEPENDENCIES} -Wl,--end-group
)
target_link_libraries(conformance_runner PRIVATE ${AT_CONFORMANCE_LIBS})

# A `make conformance_c` target: build, then run, writing results JSON.
add_custom_target(conformance_c
    COMMAND ${CMAKE_COMMAND} -E make_directory ${AT_CONFORMANCE_RESULTS}
    COMMAND ${CMAKE_COMMAND} -E echo "Running C conformance harness..."
    COMMAND $<TARGET_FILE:conformance_runner>
            ${AT_CONFORMANCE_CORPUS_JSON}
            ${AT_CONFORMANCE_RESULTS}/c-latest.json
    DEPENDS conformance_runner at_conformance_json
    USES_TERMINAL
)

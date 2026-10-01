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

# libat_zta: Zero Trust credential integration as an extension library
# (FEATURE_SPLIT_PLAN Phase 6; doc/architecture/extensions.md, "ZTA"). Reached
# from the core CMakeLists.txt when AT_ZTA is ON. It takes OpenSSL with it: the
# core needs none. What it registers is in at_zta.h.

find_package(OpenSSL REQUIRED)
message("-- libat_zta: OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_LIBRARIES}")
# Visible to the core's directory too, where the tests with a ZTA half and the
# conformance runner link libat_zta.
set_target_properties(OpenSSL::SSL OpenSSL::Crypto PROPERTIES IMPORTED_GLOBAL TRUE)

at_extension_library(zta
    SOURCES
        zta_verifier.c
        x509_verifier.c
        oidc_verifier.c
        zta_policy.c
        zta_audit.c
        zta_process.c
        zta_binding.c
        zta_identity.c
        zta_msg_types.c
)
foreach(_t at_zta at_zta_static)
    target_link_libraries(${_t} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endforeach()

at_extension_tests(zta
    zta_verifier_test
    zta_policy_test
    zta_audit_test
    zta_ocsp_test
    zta_delegation_test
    zta_link_test
)
if(TARGET zta_ocsp_test)
    foreach(_t zta_ocsp_test zta_verifier_test)
        target_compile_definitions(${_t} PRIVATE
            GEN_CA_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/test/zta_test_ca/generate_test_ca.sh")
        target_link_libraries(${_t} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endforeach()
endif()

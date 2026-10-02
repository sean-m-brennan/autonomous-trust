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

# libat_fleet: fleet consensus on updates, artifact transfer, the update and
# config-distribution processes (FEATURE_SPLIT_PLAN Phase 8). Reached from the
# core CMakeLists.txt when AT_FLEET_LIB is ON (OFF by default). It registers its
# four processes and their default subsystems, the app_fleet_propose verb and
# the FLEET_UPDATE_ACCEPTED message type.

at_extension_library(fleet
    SOURCES
        update_proposal.c
        fleet_helpers.c
        fleet_ops.c
        fleet_proc.c
        artifact_store.c
        artifact_proc_helpers.c
        artifact_proc.c
        update_proc_helpers.c
        update_selftest.c
        update_proc.c
        config_proc_helpers.c
        config_proc.c
)

at_extension_tests(fleet
    update_proposal_test
    fleet_proc_test
    artifact_store_test
    artifact_proc_test
    update_proc_test
    config_proc_test
    fleet_ext_test
)

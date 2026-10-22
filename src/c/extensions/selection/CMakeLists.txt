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

# libat_selection: R+D.md §12.7 selective assignment as an extension library
# (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md). Reached from the core CMakeLists.txt
# when AT_ORACLE_SELECTION is ON. What it registers is in at_selection.h.

at_extension_library(selection
    SOURCES
        selection.c
        selector.c
        selection_live.c
        selection_oracle.c
    DEPENDS certificates
)

at_extension_tests(selection
    selection_test
)

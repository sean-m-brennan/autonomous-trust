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

# libat_replication: the R+D.md §12.6 replicated execution layer as an extension library
# (FEATURE_SPLIT_PLAN Phase 3; doc/architecture/extensions.md, "Oracle
# layers"). Reached from the core CMakeLists.txt when AT_ORACLE_REPLICATION is ON.
# What it registers is in at_replication.h; the registration is replication_oracle.c.

at_extension_library(replication
    SOURCES
        replication.c
        sampling.c
        adjudication.c
        bisection.c
        replication_oracle.c
    DEPENDS certificates
)

at_extension_tests(replication
    replication_test
)

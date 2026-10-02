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

# libat_data_source: the data-source ingest process, the C counterpart of the
# services distribution's DataProcess (FEATURE_SPLIT_PLAN Phase 8). Reached from
# the core CMakeLists.txt when AT_DATA_SOURCE_LIB is ON (OFF by default). It
# registers its process and its default "data-source" subsystem.

at_extension_library(data_source
    SOURCES
        data_source_proc.c
)

at_extension_tests(data_source
    data_source_test
)

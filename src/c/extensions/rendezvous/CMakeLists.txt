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

# libat_rendezvous: reaching a node across NAT (FEATURE_SPLIT_PLAN Phase 7b;
# doc/architecture/rendezvous.md). Reached from the core CMakeLists.txt when
# AT_RENDEZVOUS_LIB is ON (the default). It holds the relay client and server,
# signed reachability records, the seed list and community rosters, and the
# network process's relay routes (rdv_net.c). First contact depends on it.

at_extension_library(rendezvous
    SOURCES
        net_relay.c
        net_relay_seeds.c
        net_relay_rosters.c
        reach.c
        rdv_net.c
        rdv_roster.c
)
install(FILES at_rendezvous.h DESTINATION include)

at_extension_tests(rendezvous
    net_relay_test
    net_relay_seeds_test
    net_relay_rosters_test
)

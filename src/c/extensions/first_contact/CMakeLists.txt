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

# libat_first_contact: first contact as an extension library (FEATURE_SPLIT_PLAN
# Phase 7; doc/architecture/first-contact.md). Reached from the core
# CMakeLists.txt when AT_FIRST_CONTACT_LIB is ON (the default). It holds the
# contact store and invitations, the 1:1 handshake, the directory and area-hub
# flows, devices, siblings and the backup, the app ABI (at_first_contact.h), and
# the directory registry and area hub that plug into the relay as server ops.
# It rides the relays of libat_rendezvous, which it depends on.

at_extension_library(first_contact
    SOURCES
        contact.c
        store.c
        invitation.c
        directory.c
        area_card.c
        backup.c
        device.c
        siblings.c
        sync.c
        first_contact.c
        directory_contact.c
        area_contact.c
        device_contact.c
        sibling_sync.c
        backup_contact.c
        first_contact_app.c
        net_registry.c
        net_hub.c
        fc_net.c
    DEPENDS rendezvous
)
install(FILES at_first_contact.h DESTINATION include)

at_extension_tests(first_contact
    contacts_device_test
    contacts_sync_test
    contacts_backup_test
    device_contact_test
    directory_contact_test
    directory_test
    first_contact_app_test
    first_contact_endpoint_test
    net_hub_test
    net_registry_test
    sibling_sync_test
    first_contact_live_test
)
if(TARGET first_contact_live_test)
    # Two real daemons on 127.0.0.1/.2 (~10 s). Labelled so a quick run can
    # skip it: `ctest -LE live`.
    set_tests_properties(first_contact_live_test PROPERTIES TIMEOUT 240 LABELS live)
endif()

# The contacts conformance protocol is first contact's own; the identity and
# negotiation adapters' first-contact halves compile when this library is built
# (src/c/conformance/CMakeLists.txt).
at_conformance_adapter(PROTOCOL contacts RUN at_contacts_run
    SOURCES conformance/contacts_adapter.c
    LIBS at_first_contact_static)

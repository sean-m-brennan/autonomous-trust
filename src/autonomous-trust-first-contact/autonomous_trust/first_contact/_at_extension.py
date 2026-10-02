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
"""How the core finds first contact (see ``autonomous_trust.core.extensions``):
named by the ``autonomous_trust.extensions`` entry points when installed, found
by file name in a source tree.

Two extensions, as C registers two hooks (first_contact.c's at_extension_t and
fc_net.c's net_ext_t): the handshake, gated by ``AT_FIRST_CONTACT``, and its
network half -- the directory and area-hub clients and the registry and hub
our relay serves -- which answers identity's local verbs whether or not the
handshake is on.
"""
from autonomous_trust.first_contact.fc_net import EXTENSION as NETWORK_EXTENSION
from autonomous_trust.first_contact.first_contact import EXTENSION

EXTENSIONS = (EXTENSION, NETWORK_EXTENSION)

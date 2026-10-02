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
"""Rendezvous: reaching a node across NAT (Python parity with libat_rendezvous,
src/c/extensions/rendezvous). The relay client and server (relay.py), signed
reachability records (reach.py), the signed seed list and community rosters
(relay_seeds.py, relay_rosters.py), the network process's relay routes
(rdv_net.py), the roster app verbs (roster.py), and the extension and the
services that ride the relays (rendezvous.py).
"""

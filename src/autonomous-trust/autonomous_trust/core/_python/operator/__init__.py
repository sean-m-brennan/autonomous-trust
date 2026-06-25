# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Operator-access core: PIV+MFA-authenticated human operator of an AT node.

A human operator authenticates with PIV (CAC/PIV smartcard) + MFA to
activate/connect a local AutonomousTrust node, then discovers resources on the
AT network and issues requests to it. This package holds the node-side core
(the terminal UI is the separate ``autonomous-trust-operator`` package, which
talks to the node only through the existing ``external_control`` /
``external_feedback`` queues).

Modules (added across phases P1-P5; see PIV_MFA_OPERATOR_ACCESS_PLAN.md §9):
  * ``activate``           -- PIV+MFA activation, credential->Identity binding (P1/P2)
  * ``session``            -- session lifecycle: card-removal, idle, step-up (P2)
  * ``operator_node``      -- ``AutonomousTrust`` subclass + ``OperatorProcess`` (P3)
  * ``resource_directory`` -- resources x providers x my-reach read-model (P3)

At P0 this is scaffolding only.
"""

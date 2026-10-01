# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
"""PIV / CAC smartcard verification (PKCS#11-backed) for the operator console.

A `PivVerifier` (P1) implements the ZTA `Verifier` interface backed by PKCS#11:
it reads the PIV authentication certificate, validates its chain/expiry/
revocation by delegating to `X509Verifier`, and proves possession+PIN via a
PKCS#11 challenge-response signature. It composes into an `MfaChain` as the
primary factor. See PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.1.

This package is intentionally empty at P0 (scaffolding only); the verifier and
PKCS#11 binding land in P1.
"""

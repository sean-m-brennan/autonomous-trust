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
"""ZTA credential verification (Python parity with src/c/autonomous_trust/zta).

See doc/architecture/zta-python-parity.md and doc/architecture/zta-integration.md.
"""
from .zta_verifier import (ZtaStatus, ZtaResult, Verifier, NullVerifier,
                           OidcVerifier, X509Verifier, ZTA_HASH_LEN,
                           ZTA_CRED_MAX)
from .mfa import MfaChain, CombinePolicy, MfaCredential
from .totp import (TotpVerifier, generate_totp_secret, totp_provisioning_uri,
                   totp_now)
from .zta_policy import (ZtaPolicy, BINDING_MODES, BINDING_MODE_OFF,
                         BINDING_MODE_PREFER, BINDING_MODE_REQUIRE)

__all__ = ['ZtaStatus', 'ZtaResult', 'Verifier', 'NullVerifier', 'OidcVerifier',
           'X509Verifier', 'MfaChain', 'CombinePolicy', 'MfaCredential',
           'TotpVerifier', 'generate_totp_secret', 'totp_provisioning_uri',
           'totp_now', 'ZtaPolicy', 'ZTA_HASH_LEN', 'ZTA_CRED_MAX',
           'BINDING_MODES', 'BINDING_MODE_OFF', 'BINDING_MODE_PREFER',
           'BINDING_MODE_REQUIRE']

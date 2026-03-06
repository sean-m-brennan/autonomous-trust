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

# Native C-backed wrappers (available under prefixed names)
from ._native_wrappers import (
    TransactionHistory as NativeTransactionHistory,
    Reputations as NativeReputations,
    reputation_compute as native_reputation_compute,
)

# API-compatible exports from Python backend
from ..._python.reputation.protocol import ReputationProtocol
from ..._python.reputation.reputation import TransactionHistory, Reputations, TransactionScore
from ..._python.reputation.repprocess import ReputationProcess

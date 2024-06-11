# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from uuid import uuid4
import pytest

from autonomous_trust.core.structures.merkle import MerkleTree, SimplestBlob


class ABlob(SimplestBlob):
    @property
    def designation(self) -> bytes:
        return str(self.uuid).encode()


def test_insert_blob():
    mt = MerkleTree()
    for _ in range(100):
        ident = uuid4()
        mt.insert(ABlob(mt.root_digest, ident))


def test_reinsert():
    mt = MerkleTree()
    ident = uuid4()
    for _ in range(30):
        mt.insert(ABlob(mt.root_digest, ident))


def test_merge():
    mt = MerkleTree()
    for _ in range(100):
        ident = uuid4()
        mt.insert(ABlob(mt.root_digest, ident))
    mt.merge(list(mt.blobs))

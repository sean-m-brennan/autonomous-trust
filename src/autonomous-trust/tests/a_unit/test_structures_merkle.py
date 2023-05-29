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

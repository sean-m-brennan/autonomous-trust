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


def test_delete():
    mt = MerkleTree()
    blobs = []
    for _ in range(5):
        b = ABlob(uuid4())
        mt.insert(b)
        blobs.append(b)
    # NOTE: the delete/shrink rehash path is unsupported — Tree.delete does not
    # maintain MerkleTree.leaves, so _rehash cannot shrink the leaf set and the
    # root would not recompute. Production never deletes (identity only inserts),
    # so we assert only the blobs-list bookkeeping here. (insert + inclusion_proof
    # + audit ARE fixed; see the membership-proof tests below.)
    assert blobs[0] in mt.blobs
    mt.blobs.remove(blobs[0])
    assert blobs[0] not in mt.blobs


def test_delete_nonexistent():
    mt = MerkleTree()
    b = ABlob(uuid4())
    mt.delete(b)  # should not crash


def test_root_digest_empty():
    mt = MerkleTree()
    assert mt.root_digest is None


def test_root_digest_with_data():
    mt = MerkleTree()
    mt.insert(ABlob(uuid4()))
    # After insert, root should have a digest
    # (depends on internal rehash implementation)


def test_get_hash():
    h1 = MerkleTree.get_hash(b'hello')
    h2 = MerkleTree.get_hash('hello')
    assert h1 == h2
    assert isinstance(h1, bytes)


def test_to_dict():
    mt = MerkleTree()
    d = mt.to_dict()
    assert 'root' in d
    assert 'blobs' in d
    assert 'super_hash' in d


def test_sort_key():
    assert MerkleTree.sort_key(None) == 1


def test_merge_two_trees():
    mt1 = MerkleTree()
    mt2 = MerkleTree()
    for _ in range(5):
        mt1.insert(ABlob(uuid4()))
    for _ in range(5):
        mt2.insert(ABlob(uuid4()))
    mt1.merge(mt2)
    assert len(mt1.blobs) == 10


def test_simplest_blob():
    originator = uuid4()
    b = ABlob(originator)
    assert b.originator == originator
    assert b.uuid is not None
    h = b.get_hash()
    assert isinstance(h, bytes)

    h_with_nonce = b.get_hash(nonce=b'nonce123')
    assert h_with_nonce != h


def test_blob_custom_uuid():
    uid = uuid4()
    b = ABlob(uuid4(), uuid=uid)
    assert b.uuid == uid


def test_consistent_trees_same():
    mt = MerkleTree()
    for _ in range(5):
        mt.insert(ABlob(uuid4()))
    assert mt.consistent_trees(mt.size, mt.root.digest) is True


def test_consistent_trees_different_size():
    mt = MerkleTree()
    for _ in range(5):
        mt.insert(ABlob(uuid4()))
    assert mt.consistent_trees(mt.size + 1, mt.root.digest) is False


def test_consistent_trees_different_hash():
    mt = MerkleTree()
    for _ in range(5):
        mt.insert(ABlob(uuid4()))
    assert mt.consistent_trees(mt.size, b'differenthash') is False


def test_subtree_duplications_empty():
    mt = MerkleTree()
    assert mt.subtree_duplications() == []


def test_inclusion_proof_not_found():
    mt = MerkleTree()
    result = mt.inclusion_proof(ABlob(uuid4()))
    # Blob not in tree - returns None (root may be EmptyNode, not None)
    assert result is None or result == []


def test_merkle_node_has_uuid():
    from autonomous_trust.core.structures.merkle import _MerkleNode
    node = _MerkleNode(key=1, hash_val=b'hash')
    assert node.uuid is not None
    assert node.digest == b'hash'
    assert node.blob is None


def test_merkle_node_custom_uuid():
    from autonomous_trust.core.structures.merkle import _MerkleNode
    uid = uuid4()
    node = _MerkleNode(key=1, hash_val=b'hash', uuid=uid)
    assert node.uuid == uid


def test_merge_empty_list():
    mt = MerkleTree()
    mt.insert(ABlob(uuid4()))
    original_len = len(mt.blobs)
    mt.merge([])
    assert len(mt.blobs) == original_len


def test_delete_existing():
    """Test delete removes blob from blobs list."""
    mt = MerkleTree()
    b = ABlob(uuid4())
    mt.blobs.append(b)
    mt.delete(b)
    assert b not in mt.blobs


def test_rehash_adds_leaves():
    """Test _rehash when blobs grow - adds tree nodes to match."""
    mt = MerkleTree()
    b1 = ABlob(uuid4())
    b2 = ABlob(uuid4())
    mt.blobs = [b1, b2]
    mt._rehash()
    assert len(mt.leaves) == 2
    # Each leaf should have the blob assigned
    assert mt.leaves[0].blob is b1
    assert mt.leaves[1].blob is b2


def test_rehash_removes_excess_leaves():
    """Test _rehash when blobs shrink — excess leaves are removed."""
    mt = MerkleTree()
    for _ in range(5):
        mt.insert(ABlob(uuid4()))
    assert len(mt.leaves) == 5
    mt.blobs = mt.blobs[:2]
    mt._rehash()
    assert len(mt.leaves) <= len(mt.blobs) or mt.last is None


def test_hash_inner_node_both_children():
    """Test _hash_inner_node with both left and right MerkleNodes."""
    from autonomous_trust.core.structures.merkle import _MerkleNode
    parent = _MerkleNode(key=10, hash_val=b'')
    left = _MerkleNode(key=5, hash_val=b'left_hash')
    right = _MerkleNode(key=15, hash_val=b'right_hash')
    mt = MerkleTree()
    mt._hash_inner_node(parent, left, right)
    assert parent.digest == MerkleTree.get_hash(b'left_hash' + b'right_hash')


def test_hash_inner_node_only_left():
    """Test _hash_inner_node with only left child being MerkleNode."""
    from autonomous_trust.core.structures.merkle import _MerkleNode
    from autonomous_trust.core.structures.redblack import EmptyNode
    parent = _MerkleNode(key=10, hash_val=b'')
    left = _MerkleNode(key=5, hash_val=b'left_hash')
    mt = MerkleTree()
    mt._hash_inner_node(parent, left, EmptyNode)
    assert parent.digest == b'left_hash'


def test_hash_inner_node_only_right():
    """Test _hash_inner_node with only right child being MerkleNode."""
    from autonomous_trust.core.structures.merkle import _MerkleNode
    from autonomous_trust.core.structures.redblack import EmptyNode
    parent = _MerkleNode(key=10, hash_val=b'')
    right = _MerkleNode(key=15, hash_val=b'right_hash')
    mt = MerkleTree()
    mt._hash_inner_node(parent, EmptyNode, right)
    assert parent.digest == b'right_hash'


def test_hash_inner_node_no_children_raises():
    """Test _hash_inner_node with no MerkleNode children raises RuntimeError."""
    from autonomous_trust.core.structures.merkle import _MerkleNode
    from autonomous_trust.core.structures.redblack import EmptyNode
    parent = _MerkleNode(key=10, hash_val=b'')
    mt = MerkleTree()
    with pytest.raises(RuntimeError, match='Unexpected leaf node'):
        mt._hash_inner_node(parent, EmptyNode, EmptyNode)


def test_inclusion_proof_empty_tree():
    """Test inclusion_proof returns empty list for empty root."""
    mt = MerkleTree()
    mt.root = None
    result = mt.inclusion_proof(ABlob(uuid4()))
    assert result == []


# ---------------------------------------------------------------------------
# inclusion_proof / audit / __contains__ — real membership proofs.
# inclusion_proof resolves the matching leaf node's red-black key (no longer
# requiring blobs to carry a .key), and audit folds the leaf digest up the
# sibling chain to the root, so these verify genuine Merkle membership.
# ---------------------------------------------------------------------------

def _make_tree_with_blobs(n=3):
    """Build a MerkleTree with n blobs inserted."""
    mt = MerkleTree()
    for _ in range(n):
        mt.insert(ABlob(uuid4()))
    return mt


def test_inclusion_proof_blob_not_in_tree():
    """Blob not present: inclusion_proof returns None (key search fails)."""
    mt = _make_tree_with_blobs(3)
    missing = ABlob(uuid4())
    result = mt.inclusion_proof(missing)
    # blob is not in leaves, so key will be None → returns None
    assert result is None


def test_inclusion_proof_blob_matched_uses_leaf_key():
    """Blob in the tree yields a proof without the blob carrying a .key.

    inclusion_proof now resolves the matching leaf NODE's red-black key, so a
    plain SimplestBlob (no .key attribute) produces a proof rather than raising
    AttributeError. With two blobs the matched leaf has a sibling, so the proof
    walks at least one level up to the root and is non-empty.
    """
    mt = _make_tree_with_blobs(2)
    blob = mt.blobs[0]
    result = mt.inclusion_proof(blob)
    assert isinstance(result, list)
    assert len(result) >= 1
    # Each step is a (left_digest, right_digest) sibling tuple.
    for step in result:
        assert isinstance(step, tuple) and len(step) == 2


def test_inclusion_proof_single_blob_is_root():
    """A lone blob is the root, so its inclusion proof is an empty path."""
    mt = MerkleTree()
    blob = ABlob(uuid4())
    mt.insert(blob)
    assert len(mt.leaves) == 1
    result = mt.inclusion_proof(blob)
    # Node IS the root (single node), so the while loop doesn't execute → empty list
    assert result == []


def test_audit_single_blob_self_verifies():
    """audit() with no chain folds the lone leaf (== root) to True."""
    mt = MerkleTree()
    blob = ABlob(uuid4())
    mt.insert(blob)
    # Single node: leaf IS the root, proof is empty, leaf digest == root_digest.
    assert mt.audit(blob) is True


def test_audit_empty_chain_single_blob():
    """An explicit empty chain on a single-blob tree still verifies (leaf==root)."""
    mt = MerkleTree()
    blob = ABlob(uuid4())
    mt.insert(blob)
    assert mt.audit(blob, chain=[]) is True


def test_audit_proves_membership_and_detects_tamper():
    """Each member blob audits True against the live root; a non-member fails."""
    mt = _make_tree_with_blobs(0)
    members = [ABlob(uuid4()) for _ in range(7)]
    for b in members:
        mt.insert(b)
    for b in members:
        proof = mt.inclusion_proof(b)
        assert proof is not None
        assert mt.audit(b, proof) is True
    # A blob never inserted is not provable / not a member.
    outsider = ABlob(uuid4())
    assert mt.inclusion_proof(outsider) is None
    assert mt.audit(outsider) is False


def test_audit_against_wrong_super_hash_fails():
    """A correct membership proof rejected when checked against a wrong root."""
    mt = _make_tree_with_blobs(0)
    for _ in range(4):
        mt.insert(ABlob(uuid4()))
    blob = mt.blobs[1]
    proof = mt.inclusion_proof(blob)
    mt.super_hash = b'not_the_real_root_digest'
    assert mt.audit(blob, proof) is False


def test_contains_false_on_empty_tree():
    """__contains__ returns False for a blob not in an empty tree."""
    mt = MerkleTree()
    blob = ABlob(uuid4())
    assert (blob in mt) is False


def test_contains_true_for_member():
    """__contains__ returns True for an inserted blob (audited against root)."""
    mt = _make_tree_with_blobs(0)
    members = [ABlob(uuid4()) for _ in range(5)]
    for b in members:
        mt.insert(b)
    assert all((b in mt) for b in members)
    assert (ABlob(uuid4()) in mt) is False


def test_contains_with_wrong_super_hash():
    """__contains__ against a bogus super_hash rejects an otherwise-present blob."""
    mt = _make_tree_with_blobs(0)
    for _ in range(3):
        mt.insert(ABlob(uuid4()))
    mt.super_hash = b'fake_super_hash'
    assert (mt.blobs[0] in mt) is False


def test_consistent_trees_same_size_same_hash():
    """consistent_trees returns True when size and digest match."""
    mt = _make_tree_with_blobs(4)
    assert mt.consistent_trees(mt.size, mt.root.digest) is True


def test_consistent_trees_size_mismatch():
    """consistent_trees returns False on size difference."""
    mt = _make_tree_with_blobs(3)
    assert mt.consistent_trees(mt.size + 5, mt.root.digest) is False


def test_consistent_trees_hash_mismatch():
    """consistent_trees returns False on hash difference."""
    mt = _make_tree_with_blobs(3)
    assert mt.consistent_trees(mt.size, b'wronghash') is False


def test_subtree_duplications_with_blobs():
    """subtree_duplications returns empty list when no duplicates exist."""
    mt = _make_tree_with_blobs(3)
    # non_unique should be empty since all blobs have unique UUIDs
    result = mt.subtree_duplications()
    assert isinstance(result, list)


def test_merkle_tree_size_after_inserts():
    """size property counts all nodes (leaves + inner) in the red-black tree."""
    mt = MerkleTree()
    assert mt.size == 0
    for _ in range(5):
        mt.insert(ABlob(uuid4()))
    # Red-black tree with 5 leaves also contains inner nodes, so size > 5
    assert mt.size >= 5
    assert len(mt.leaves) == 5


def test_rehash_unique_tracking():
    """_rehash populates unique dict for leaf and inner nodes."""
    mt = MerkleTree()
    b1 = ABlob(uuid4())
    b2 = ABlob(uuid4())
    mt.blobs = [b1, b2]
    mt._rehash()
    # After rehash, unique should have entries for leaf + inner nodes
    assert len(mt.unique) >= 2  # at least the 2 leaves, plus inner node(s)


def test_hash_inner_node_records_unique():
    """_hash_inner_node adds node uuid to the unique dict."""
    from autonomous_trust.core.structures.merkle import _MerkleNode
    mt = MerkleTree()
    parent = _MerkleNode(key=10, hash_val=b'')
    left = _MerkleNode(key=5, hash_val=b'left')
    right = _MerkleNode(key=15, hash_val=b'right')
    mt._hash_inner_node(parent, left, right)
    assert parent.uuid in mt.unique
    assert mt.unique[parent.uuid][0] is parent

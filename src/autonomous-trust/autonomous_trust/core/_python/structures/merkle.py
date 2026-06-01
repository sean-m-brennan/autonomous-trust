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

from nacl.hash import blake2b
from collections import defaultdict
from abc import ABC, abstractmethod
from uuid import UUID, uuid4
from typing import Union

from .redblack import Node, Tree
from ..config import Configuration
from ..system import encoding


class SimplestBlob(ABC):
    """
    Abstract object type contained in a MerkleTree
    """
    def __init__(self, originator: UUID, uuid: UUID = None):
        self.uuid = uuid
        if uuid is None:
            self.uuid = uuid4()
        self.originator = originator

    @property
    @abstractmethod
    def designation(self) -> bytes:
        """
        Aspects about this object that are uniquely identifying, converted to bytes
        :return: bytes
        """
        return b''

    def get_hash(self, nonce: bytes = None) -> bytes:
        """
        Compute a hash over the object designation
        :param nonce: bytes
        :return: bytes
        """
        if nonce is None:
            nonce = b''
        return MerkleTree.get_hash(self.designation + nonce)


class _MerkleNode(Node, Configuration):
    def __init__(self, key, hash_val, blob=None, uuid=None, left=None, right=None, parent=None, red=False):
        super().__init__(key, None, left, right, parent, red)
        self.digest = hash_val
        self.blob = blob  # only leaves
        self.uuid = uuid
        if uuid is None:
            self.uuid = uuid4()


class MerkleTree(Tree, Configuration):
    """
    Merkle tree
    Assumes hashing is asymmetric
    """
    node_class = _MerkleNode
    hash_func = blake2b
    byte_enc = encoding

    def __init__(self, root=None, blobs=None, super_hash=None):
        super().__init__(root)
        self.blobs = blobs
        if blobs is None:
            self.blobs = []
        self.super_hash = super_hash
        self.unique = defaultdict(list)
        self.non_unique = []

    def to_dict(self):
        return dict(root=self.root, blobs=self.blobs, super_hash=self.super_hash)

    @classmethod
    def sort_key(cls, _):
        return 1  # unsorted, derived classes might override

    @classmethod
    def get_hash(cls, x: Union[bytes, str]) -> bytes:
        if not isinstance(x, bytes):
            x = x.encode(cls.byte_enc)
        return cls.hash_func(x)

    @property
    def root_digest(self):
        try:
            return self.root.digest
        except AttributeError:
            return None

    def insert(self, blob):  # noqa
        """
        Add an object as a sub-leaf, invokes a rehash of the tree
        O(nlogn) in the number of blobs
        :param blob: SimplestBlob
        :return: None
        """
        if blob not in self.blobs:
            self.blobs.append(blob)
            self._rehash()

    def merge(self, blob_list):
        """
        Merge another merkle tree
        :param blob_list: MerkleTree or list of blobs
        :return: None
        """
        if isinstance(blob_list, MerkleTree):
            blob_list = blob_list.blobs
        count = 0
        for blob in blob_list:
            if blob not in self.blobs:
                self.blobs.append(blob)
                count += 1
        self.blobs.sort(key=self.sort_key)
        if count > 0:
            self._rehash()

    def delete(self, blob):  # noqa
        """
        Remove an object as a sub-leaf, invokes a rehash of the tree
        O(nlogn) in the number of blobs
        :param blob: SimplestBlob
        :return: None
        """
        if blob in self.blobs:
            self.blobs.remove(blob)
            self._rehash()

    def _rehash(self):
        while len(self.leaves) > len(self.blobs):
            if self.last is None:
                break
            super().delete(self.last.key)
        while len(self.leaves) < len(self.blobs):
            super().insert(None)
        self.unique.clear()
        self.non_unique.clear()
        for idx, blob in enumerate(self.blobs):
            leaf = self.leaves[idx]
            leaf.blob = blob
            leaf.digest = blob.get_hash()
            self.unique[leaf.uuid].append(leaf)
            if len(self.unique[leaf.uuid]) > 1:
                self.non_unique += [node.key for node in self.unique[leaf.uuid]]
        # Collect nodes by level via BFS, then rehash inner nodes bottom-up
        if not isinstance(self.root, _MerkleNode):
            return
        nodes_by_level = defaultdict(list)
        queue = [self.root]
        while queue:
            node = queue.pop(0)
            if not isinstance(node, _MerkleNode):
                continue
            nodes_by_level[node.level].append(node)
            if isinstance(node.left, _MerkleNode):
                queue.append(node.left)
            if isinstance(node.right, _MerkleNode):
                queue.append(node.right)
        max_level = max(nodes_by_level.keys()) if nodes_by_level else 0
        for level in range(max_level, -1, -1):
            for node in nodes_by_level[level]:
                if node.is_leaf():
                    continue
                self._hash_inner_node(node)

    def _hash_inner_node(self, node, left=None, right=None):
        if left is None:
            left = node.left
        if right is None:
            right = node.right
        if not isinstance(left, self.node_class) and not isinstance(right, self.node_class):
            raise RuntimeError('Unexpected leaf node in Merkle tree')
        elif not isinstance(left, self.node_class):
            node.digest = right.digest  # do not rehash (avoid CVE-2012-2459)
        elif not isinstance(right, self.node_class):
            node.digest = left.digest  # ditto
        else:
            node.digest = self.get_hash(left.digest + right.digest)
        self.unique[node.uuid].append(node)
        if len(self.unique[node.uuid]) > 1:
            self.non_unique += [n.key for n in self.unique[node.uuid]]

    def inclusion_proof(self, blob):
        """
        Subtree chain from the root to the given blob
        :param blob: SimplestBlob
        :return: list of tuples of digest|None from siblings along the path from leaf to root
        """
        nodes = []
        if self.root is None:
            return nodes
        key = None
        for leaf in self.leaves:
            if leaf.blob == blob:
                # Use the matching leaf NODE's red-black key, not blob.key.
                # The blob (a SimplestBlob) does not carry a tree key; the
                # leaf node assigned during insert() does. The previous
                # `blob.key` read forced callers to hand-mirror the leaf key
                # onto the blob and otherwise raised AttributeError.
                key = leaf.key
                break
        if key is None:
            return None
        node = self.find(key)
        while node is not self.root:
            sib = node.sibling  # None when the sibling is the EmptyNode sentinel
            if sib is None:
                # No sibling: _hash_inner_node promotes this single child's
                # digest to the parent UNCHANGED (CVE-2012-2459 guard), so the
                # proof records a no-op step.
                nodes.append((None, None))
            elif node is node.parent.left:
                # Sibling sits on the RIGHT: parent = H(self || sibling).
                nodes.append((None, sib.digest))
            else:
                # Sibling sits on the LEFT: parent = H(sibling || self).
                nodes.append((sib.digest, None))
            node = node.parent
        return nodes

    def audit(self, blob, chain=None):
        """
        Verify blob membership by folding its leaf digest up the sibling chain
        and comparing to the expected root (``super_hash`` if set, else this
        tree's ``root_digest``).

        Each chain step is ``(left|None, right|None)`` where the non-None slot
        holds the sibling digest and its position says which side to combine on,
        matching ``inclusion_proof``/``_hash_inner_node``. ``(None, None)`` is a
        promote step (lone child) and leaves the running digest unchanged.

        :param blob: SimplestBlob
        :param chain: optional precomputed proof; defaults to ``inclusion_proof``
        :return: bool
        """
        if chain is None:
            chain = self.inclusion_proof(blob)
        if chain is None:
            return False
        digest = blob.get_hash()  # leaf digest, as set in _rehash
        for hash_tpl in chain:
            if hash_tpl == (None, None):
                continue  # promoted unchanged
            elif hash_tpl[0] is None:  # sibling on the right
                digest = self.get_hash(digest + hash_tpl[1])
            else:  # sibling on the left
                digest = self.get_hash(hash_tpl[0] + digest)
        target = self.super_hash if self.super_hash is not None else self.root_digest
        return target is not None and digest == target

    def __contains__(self, blob):
        """
        Membership test against the expected root (``super_hash`` when set,
        otherwise the local ``root_digest``).
        :param blob: SimplestBlob
        :return: bool
        """
        return self.audit(blob)

    def consistent_trees(self, other_size, other_root_hash):
        """
        Verify that two Merkle trees match
        :param other_size:
        :param other_root_hash:
        :return:
        """
        return self.size == other_size and self.root.digest == other_root_hash

    def subtree_duplications(self):
        """
        Locate any subtrees with duplicate hashes (and thus a duplicate data sequence)
        :return: list of roots of duplicated subtrees
        """
        return [self.find(key) for key in set(self.non_unique)]

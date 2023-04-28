from nacl.hashlib import blake2b

from ...config import Configuration
from .tree import Node, Tree


class SimplestBlock(object):
    def __init__(self, sig):
        self.sig: bytes = sig


class MerkleNode(Node, Configuration):
    def __init__(self, key, hash_val, block=None):
        super().__init__(key, None)
        self.digest = hash_val
        self.block = block  # only leaves


class MerkleTree(Tree):
    """
    Merkle tree
    """
    node_class = MerkleNode
    hash_func = blake2b

    def __init__(self, root=None, blocks=None, super_hash=None):
        super().__init__(root)
        self.blocks = blocks
        if blocks is None:
            self.blocks = blocks
        self.super_hash = super_hash

    @classmethod
    def _hashing(cls, x):
        if not isinstance(x, bytes):
            x = x.encode('utf-8')
        return cls.hash_func(x).hexdigest()

    def insert(self, block):  # noqa
        """
        Add a data block as a sub-leaf, invokes a rehash of the tree
        O(nlogn) in the number of blocks
        :param block: SimplestBlock
        :return: None
        """
        if block not in self.blocks:
            self.blocks.append(block)
            self._rehash()

    def delete(self, block):  # noqa
        """
        Remove a data block as a sub-leaf, invokes a rehash of the tree
        O(nlogn) in the number of blocks
        :param block: SimplestBlock
        :return: None
        """
        if block in self.blocks:
            self.blocks.remove()
            self._rehash()

    def _rehash(self):
        while len(self.leaves) > len(self.blocks):
            super().delete(self.last)
        while len(self.leaves) < len(self.blocks):
            super().insert(None)
        for idx, block in enumerate(self.blocks):
            leaf = self.leaves[idx]
            leaf.block = block
            leaf.digest = self._hashing(block.sig)
        for level in range(len(self), -1, -1):
            level_nodes = []  # get nodes at level
            for node in level_nodes:
                if node.is_leaf():
                    continue
                self._hash_inner_node(node)

    def _hash_inner_node(self, node, left=None, right=None):
        if left is None:
            left = node.left
        if right is None:
            right = node.right
        if not isinstance(left, MerkleNode):
            node.digest = self._hashing(right.digest)
        elif not isinstance(right, MerkleNode):
            node.digest = self._hashing(left.digest)
        else:
            node.digest = self._hashing(left.digest + right.digest)

    def root_to_block(self, block):
        """
        Subtree chain from the root to the given block
        :param block: SimplestBlock
        :return: list of tuples of digest|None from siblings along the path from leaf to root
        """
        nodes = []
        if self.root is None:
            return nodes
        key = None
        for leaf in self.leaves:
            if leaf.block == block:
                key = block.key
                break
        if key is None:
            return None
        node = self.find(key)
        while node != self.root:
            if node.sibling == self.empty:
                nodes.append((None, None))
            elif node == node.parent.left:
                nodes.append((None, node.right.digest))
            else:
                nodes.append((node.left.digest, None))
            node = node.parent
        return nodes

    def audit(self, block, chain=None):
        """
        Verify block membership given a subtree chain and a super-hash (root hash or off-tree)
        Off-tree chain must have this tree's root as the leaf
        O(n) in chain length, or O(logn) in number of blocks in the tree(s)
        :param block: SimplestBlock
        :param chain: list of tuples of digest|None from siblings along the path from leaf to root
        :return: bool
        """
        if chain is None:
            chain = self.root_to_block(block)  # my own
        if chain[-1].digest != self.root.digest:  # noqa
            chain = self.root_to_block(block) + chain  # append local to super-chain
        # if chain[0].digest != self._hashing(block.sig):  # noqa
        #    return False
        digest = self._hashing(block.sig)
        for hash_tpl in chain:
            if hash_tpl == (None, None):
                digest = self._hashing(digest)
            elif hash_tpl[0] is None:  # i.e. digest was from the right
                digest = self._hashing(digest + hash_tpl[1])  # noqa
            else:
                digest = self._hashing(hash_tpl[1] + digest)  # noqa
        return digest == self.super_hash

    def __contains__(self, block):
        """
        Membership test, assumes we usually want to test a non-local block
        :param block: SimplestBlock
        :return: bool
        """
        root_hash = self.root.digest
        if self.super_hash is not None:
            root_hash = self.super_hash
        return self.verify(block, root_hash)

    def consistent(self, other_root, other_size):
        """
        Verify that two Merkle trees match
        :param other_root:
        :param other_size:
        :return:
        """
        # FIXME consistency proof

    # FIXME duplicate subtree detection
    def findDuplicateSubtrees(self, root):
        def merkle(node):
            if not node:
                return '#'
            m_left = merkle(node.left)
            m_right = merkle(node.right)
            node.merkle = self._hashing(m_left + str(node.val) + m_right)
            count[node.merkle].append(node)
            return node.merkle

        count = collections.defaultdict(list)
        merkle(root)
        return [nodes.pop() for nodes in count.values() if len(nodes) >= 2]
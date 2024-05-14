from collections.abc import Iterable
from enum import Enum
from typing import Union, Optional


def _flatten(xs):
    for x in xs:
        if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
            yield from _flatten(x)
        else:
            yield x


class _Direction(Enum):
    left = 0
    right = 1

    def incr(self):
        return _Direction((self.value + 1) % 2)


class Node(object):
    """
    Red/Black tree node
    """

    def __init__(self, key, data, left=None, right=None, parent=None, red=False):
        self.key = key
        self.data = data
        self.parent = parent
        self.left = left
        self.right = right
        self.red = red

    def get_child(self, which):
        """
        Gets the given child
        :param which: Direction (left or right)
        :return: Node
        """
        if which == _Direction.left:
            return self.left
        return self.right

    def set_child(self, which, node):
        """
        Sets value of the given child
        :param which: Direction (left or right)
        :param node: node to assign
        :return: None
        """
        if which == _Direction.left:
            self.left = node
        else:
            self.right = node

    @property
    def sibling(self):
        if self.parent is None:
            return None
        if self == self.parent.left:
            sibling = self.parent.right
        else:
            sibling = self.parent.left
        if not isinstance(sibling, Node):
            return None
        return sibling

    @property
    def level(self):
        """
        Depth from root (root is level 0)
        :return: int
        """
        node = self.parent
        level = 0
        while node is not None:
            level += 1
            node = node.parent
        return level

    def is_leaf(self):
        return not isinstance(self.left, Node) and not isinstance(self.right, Node)

    def leaves(self):
        """
        Dynamically finds leaf nodes (have no children)
        Warning: recursive
        :return: list of Nodes
        """
        if self.is_leaf():
            return [self]
        leaves = []
        if isinstance(self.left, Node):
            leaves += self.left.leaves()
        if isinstance(self.right, Node):
            leaves += self.right.leaves()
        return leaves

    def to_tuple(self):
        """
        Encode structure (but not data) as a nested tuple
        :return: tuple
        """
        left_tpl = ()
        right_tpl = ()
        if self.left and isinstance(self.left, Node):
            left_tpl = self.left.to_tuple()
        if self.right and isinstance(self.right, Node):
            right_tpl = self.right.to_tuple()
        return self.key, left_tpl, right_tpl

    @classmethod
    def from_tuple(cls, tpl):
        """
        Recover structure (but not data) from a nested tuple
        Warning: recursive
        :param tpl: nested tuple
        :return: Tree
        """
        if len(tpl) < 1:
            return None
        left = None
        right = None
        if len(tpl) > 1:
            left = cls.from_tuple(tpl[1])
        if len(tpl) > 2:
            right = cls.from_tuple(tpl[2])
        return cls(tpl[0], None, left, right)


class EmptyNodeType(object):
    """
    Red/Black sentinel
    """
    _self = None
    red = False

    def __new__(cls):
        if cls._self is None:
            cls._self = super().__new__(cls)
        return cls._self

    # def __init__(self):
    #    self.red = False


EmptyNode = EmptyNodeType()


class DuplicateKey(RuntimeError):
    pass


class Tree(object):
    """
    Red/Black balanced tree
    """
    node_class = Node

    def __init__(self, root=None):
        self.root = root
        if root is None:
            self.root = EmptyNode
            self.leaves = []
            self.first = None
            self.last = None
        else:
            self.leaves = self.root.leaves()
            keys = sorted(list(_flatten(self.to_tuple())))
            self.first = self.find(keys[0])
            self.last = self.find(keys[-1])
        self.node_count = 0

    @property
    def size(self):
        """
        Total number of nodes
        Warning: recursive
        :return: int
        """
        tpl = self.to_tuple()
        if len(tpl) > 0:
            return len(list(_flatten(self.to_tuple())))
        return 0

    def __len__(self):
        """
        Depth of tree
        :return: int
        """
        depth = 0
        for leaf in self.leaves:
            if leaf.level > depth:
                depth = leaf.level
        return depth

    def insert(self, data, key=None):
        """
        Data insertion into tree, key is optional
        :param data: Any
        :param key: int
        :return: None
        """
        self.node_count += 1
        if key is None:
            #key = self.size + 1  # auto-assign key
            key = self.node_count  # auto-assign key
        node = self.node_class(key, data, left=EmptyNode, right=EmptyNode, red=True)
        if self.first is None or self.first.key > key:
            self.first = node
        if self.last is None or self.last.key < key:
            self.last = node
        self.leaves.append(node)
        parent = None
        current = self.root
        while current is not EmptyNode:
            parent = current
            if node.key < current.key:
                current = current.left
            elif node.key > current.key:
                current = current.right
            else:
                raise DuplicateKey(key)

        node.parent = parent
        if parent is None:
            self.root = node
        elif node.key < parent.key:
            parent.left = node
        else:
            parent.right = node
        if parent in self.leaves:
            self.leaves.remove(parent)
        self._recolor_insert(node)

    def _rotate(self, d_enum, node):
        direction = d_enum
        counter = d_enum.incr()
        pivot = node.get_child(counter)
        node.set_child(counter, pivot.get_child(direction))
        if pivot.get_child(direction) is not EmptyNode:
            pivot.get_child(direction).parent = node
        if node.left is EmptyNode and node.right is EmptyNode:
            self.leaves.append(node)

        pivot.parent = node.parent
        if node.parent is None:
            self.root = pivot
        elif node == node.parent.get_child(direction):
            node.parent.set_child(direction, pivot)
        else:
            node.parent.set_child(counter, pivot)
        pivot.set_child(direction, node)
        node.parent = pivot
        if pivot in self.leaves:
            self.leaves.remove(pivot)

    def _recolor_insert(self, node):  # TODO reduce verbosity (duplication)
        while node != self.root and node.parent.red:
            if node.parent == node.parent.parent.right:
                if node.parent.parent.left.red:
                    node.parent.parent.left.red = False
                    node.parent.red = False
                    node.parent.parent.red = True
                    node = node.parent.parent
                else:
                    if node == node.parent.left:
                        node = node.parent
                        self._rotate(_Direction.right, node)
                    node.parent.red = False
                    node.parent.parent.red = True
                    self._rotate(_Direction.left, node.parent.parent)
            else:
                if node.parent.parent.right.red:
                    node.parent.parent.right.red = False
                    node.parent.red = False
                    node.parent.parent.red = True
                    node = node.parent.parent
                else:
                    if node == node.parent.right:
                        node = node.parent
                        self._rotate(_Direction.left, node)
                    node.parent.red = False
                    node.parent.parent.red = True
                    self._rotate(_Direction.right, node.parent.parent)
        self.root.red = False

    def delete(self, key):
        node = self.find(key)
        if node is None:
            return
        if node.parent is None:
            self.first = self.last = None
        elif self.first is not None and key == self.first.key:
            self.first = node.parent
        elif self.last is not None and key == self.last.key:
            self.last = node.parent
        temp = node
        color = temp.red
        if node.left is EmptyNode:
            fix_root = node.right
            self._transplant(node, node.right)
        elif node.right is EmptyNode:
            fix_root = node.left
            self._transplant(node, node.left)
        else:  # both
            temp = self._min_leaf(node.right)
            color = temp.red
            fix_root = temp.right
            if temp.parent == node:
                fix_root.parent = temp
            else:
                self._transplant(temp, temp.right)
                temp.right = node.right
                temp.right.parent = temp
            self._transplant(node, temp)
            temp.left = node.left
            temp.left.parent = temp
            temp.red = node.red
        if not color:
            self._recolor_del(fix_root)
        self.node_count -= 1

    @staticmethod
    def _min_leaf(node):
        all_leaves = node.leaves()
        min_key = min([leaf.key for leaf in all_leaves])
        return [leaf for leaf in all_leaves if leaf.key == min_key][0]

    def _transplant(self, u, v):
        if u.parent is None:
            self.root = v
        elif u == u.parent.left:
            u.parent.left = v
        else:
            u.parent.right = v
        v.parent = u.parent

    def _recolor_del(self, node):  # TODO reduce verbosity (duplication)
        while node != self.root and not node.red:
            if node == node.parent.left:
                sibling = node.parent.right
                if sibling.red:
                    sibling.red = False
                    node.parent.red = True
                    self._rotate(_Direction.left, node.parent)
                    sibling = node.parent.right
                if not sibling.left.red and not sibling.right.red:
                    sibling.red = True
                    node = node.parent
                else:
                    if not sibling.right.red:
                        sibling.left.red = False
                        sibling.red = True
                        self._rotate(_Direction.right, sibling)
                        sibling = node.parent.right
                    sibling.red = node.parent.red
                    node.parent.red = False
                    sibling.right.red = False
                    self._rotate(_Direction.left, node.parent)
                    node = self.root
            else:  # node is right child
                sibling = node.parent.left
                if sibling.red:
                    sibling.red = False
                    node.parent.red = True
                    self._rotate(_Direction.right, node.parent)
                    sibling = node.parent.left
                if not sibling.left.red and not sibling.right.red:
                    sibling.red = True
                    node = node.parent
                else:
                    if not sibling.left.red:
                        sibling.right.red = False
                        sibling.red = True
                        self._rotate(_Direction.left, sibling)
                        sibling = node.parent.left

                    sibling.red = node.parent.red
                    node.parent.red = False
                    sibling.left.red = False
                    self._rotate(_Direction.right, node.parent)
                    node = self.root
        node.red = False

    def find(self, key) -> Optional[Node]:
        """
        Find the Node at key
        :param key: int
        :return: Node
        """
        current = self.root
        while current is not EmptyNode:
            if key < current.key:
                current = current.left
            elif key > current.key:
                current = current.right
            else:
                return current
        return None

    def to_tuple(self):
        """
        Encode structure (but not data) as a nested tuple
        :return: tuple
        """
        try:
            return self.root.to_tuple()
        except AttributeError:
            return ()

    @classmethod
    def from_tuple(cls, tpl):
        """
        Recover structure (but not data) from a nested tuple
        Warning: recursive
        :param tpl: nested tuple
        :return: Tree
        """
        if len(tpl) < 1:
            return cls()
        left = None
        right = None
        if len(tpl) > 1:
            left = cls.node_class.from_tuple(tpl[1])
        if len(tpl) > 2:
            right = cls.node_class.from_tuple(tpl[2])
        return cls(cls.node_class(tpl[0], None, left, right))

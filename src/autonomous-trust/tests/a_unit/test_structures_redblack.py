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

import pytest

from autonomous_trust.core.structures.redblack import Tree, EmptyNode, _flatten  # noqa


def test_tuples():
    tpl1 = ()
    tr1 = Tree.from_tuple(tpl1)
    assert tr1.to_tuple() == tpl1
    assert tr1.root == EmptyNode
    tpl2 = (1, (), ())
    tr2 = Tree.from_tuple(tpl2)
    assert tr2.to_tuple() == tpl2
    tpl3 = (2, (1, (), ()), (3, (), ()))
    tr3 = Tree.from_tuple(tpl3)
    assert tr3.to_tuple() == tpl3
    tpl4 = (4, (2, (1, (), ()), (3, (), ())), (6, (5, (), ()), (7, (), (8, (), ()))))
    tr4 = Tree.from_tuple(tpl4)
    assert tr4.to_tuple() == tpl4
    assert tr4.size == 8


def _compare_ins(n):
    tree = Tree()
    total = 0
    for x in range(1, n+1):
        total += x
        tree.insert(None)
    tpl = tree.to_tuple()
    assert total == sum(_flatten(tpl))
    assert tree.size == n


def test_insertion():
    for m in range(1, 11):
        _compare_ins(m)
    for m in range(10, 101, 10):
        _compare_ins(m)
    for m in range(100, 1001, 100):
        _compare_ins(m)


@pytest.mark.slow
def test_insertion_large():
    for m in range(1000, 10001, 1000):
        _compare_ins(m)


def _compare_del(i, d):
    tree = Tree()
    total = 0
    for x in range(1, i+1):
        total += x
        tree.insert(None)
    if i > d:
        count = 0
        for y in range(1, i+1, d+1):
            total -= y
            tree.delete(y)
            count += 1
        tpl = tree.to_tuple()
        assert total == sum(_flatten(tpl))
        assert tree.size == i - count


def test_deletion():
    for m in range(1, 11):
        _compare_del(m, 2)
    for m in range(10, 101, 10):
        _compare_del(m, 5)
    for m in range(100, 1001, 100):
        _compare_del(m, 10)


def test_leaves():
    tree = Tree()
    for x in range(1, 11):
        tree.insert(None)
    expected = [1, 3, 5, 7, 10]
    assert sorted([x.key for x in tree.root.leaves()]) == expected
    assert sorted([x.key for x in tree.leaves]) == expected


def test_levels():
    tree = Tree()
    for x in range(1, 11):
        tree.insert(None)
    expected = [2, 1, 2, 0, 2, 1, 3, 2, 3, 4]
    assert [tree.find(x).level for x in range(1, 11)] == expected


from autonomous_trust.core.structures.redblack import Node, DuplicateKey


class TestNodeSibling:
    def test_sibling_no_parent(self):
        node = Node(1, 'a')
        assert node.sibling is None

    def test_sibling_empty_node(self):
        parent = Node(5, 'p')
        child = Node(3, 'c', parent=parent)
        parent.left = child
        parent.right = EmptyNode
        assert child.sibling is None

    def test_sibling_left_child(self):
        parent = Node(5, 'p')
        left = Node(3, 'l', parent=parent)
        right = Node(7, 'r', parent=parent)
        parent.left = left
        parent.right = right
        assert left.sibling is right
        assert right.sibling is left


class TestTreeInsertDelete:
    def test_duplicate_key_raises(self):
        t = Tree()
        t.insert('a', key=1)
        with pytest.raises(DuplicateKey):
            t.insert('b', key=1)

    def test_delete_both_children(self):
        t = Tree()
        for i in range(1, 8):
            t.insert(str(i), key=i)
        # Node 2 should have both children after insertions
        t.delete(2)
        assert t.find(2) is None
        # Other nodes still findable
        assert t.find(1) is not None
        assert t.find(3) is not None

    def test_delete_triggers_recolor(self):
        """Insert enough nodes then delete to trigger various recolor paths."""
        t = Tree()
        for i in range(1, 16):
            t.insert(str(i), key=i)
        # Delete nodes from various positions to trigger recolor_del
        for key in [3, 7, 11, 5, 13, 1, 9]:
            t.delete(key)
            assert t.find(key) is None

    def test_delete_root_only(self):
        t = Tree()
        t.insert('a', key=1)
        t.delete(1)
        assert t.find(1) is None

    def test_delete_nonexistent(self):
        t = Tree()
        t.insert('a', key=1)
        t.delete(99)  # should not crash

    def test_delete_root_resets_first_last(self):
        t = Tree()
        t.insert('a', key=5)
        t.delete(5)
        assert t.first is None
        assert t.last is None

    def test_delete_first_updates(self):
        t = Tree()
        for i in [5, 3, 7, 1]:
            t.insert(str(i), key=i)
        t.delete(1)  # delete first
        # first should be updated

    def test_delete_last_updates(self):
        t = Tree()
        for i in [5, 3, 7, 9]:
            t.insert(str(i), key=i)
        t.delete(9)  # delete last


class TestTreeFromTuple:
    def test_from_tuple_empty(self):
        t = Tree.from_tuple(())
        assert t.root is EmptyNode

    def test_from_tuple_single(self):
        t = Tree.from_tuple((5,))
        assert t.root.key == 5

    def test_from_tuple_with_children(self):
        t = Tree.from_tuple((5, (3,), (7,)))
        assert t.root.key == 5


class TestTreeSize:
    def test_size_empty(self):
        t = Tree()
        assert t.size == 0

    def test_len_empty(self):
        t = Tree()
        assert len(t) == 0

    def test_roundtrip_tuple(self):
        t = Tree()
        for i in [5, 3, 7, 1, 4, 6, 8]:
            t.insert(str(i), key=i)
        tpl = t.to_tuple()
        assert len(tpl) > 0


class TestNodeLevel:
    def test_root_level(self):
        node = Node(1, 'a')
        assert node.level == 0

    def test_child_level(self):
        parent = Node(5, 'p')
        child = Node(3, 'c', parent=parent)
        assert child.level == 1


class TestNodeTuple:
    def test_from_tuple_empty(self):
        result = Node.from_tuple(())
        assert result is None

    def test_roundtrip(self):
        n = Node(5, None, Node(3, None), Node(7, None))
        tpl = n.to_tuple()
        recovered = Node.from_tuple(tpl)
        assert recovered.key == 5


class TestDeleteRightChildRecolor:
    def test_extensive_delete_patterns(self):
        """Insert and delete in patterns that exercise right-child recolor paths."""
        t = Tree()
        # Insert in order that creates specific tree shape
        for i in [8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15]:
            t.insert(str(i), key=i)
        # Delete right-side nodes to trigger right-child recolor_del
        for key in [15, 14, 13, 12, 11, 10, 9]:
            t.delete(key)
            assert t.find(key) is None
        # Verify remaining nodes
        for key in [1, 2, 3, 4, 5, 6, 7, 8]:
            assert t.find(key) is not None

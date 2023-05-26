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


@pytest.mark.skip(reason="too long")
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

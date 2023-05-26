from abc import ABC, abstractmethod
from uuid import UUID, uuid4
from datetime import datetime
from copy import deepcopy
from collections import defaultdict
import random
import string

from ..config import Configuration
from ..system import now

class Step(ABC):
    def __init__(self, uuid):  # FIXME
        self.uuid = None


class GenesisType(Step):
    """
    Singleton root of every chain or graph
    """
    _self = None

    def __new__(cls):
        if cls._self is None:
            cls._self = super().__new__(cls)
        return cls._self

    def __init__(self):
        super().__init__(UUID('{00000000-0000-0000-0000-000000000000}'))


Genesis = GenesisType()


class LinkedStep(Step, Configuration):
    """
    A link in a DAG
    From any link, can only navigate in a chain back to the root
    """
    def __init__(self, payload=None, uuid: UUID = None, timestamp: datetime = None,
                 parent: Step = None, previous=None):
        if uuid is None:
            uuid = uuid4()
        super().__init__(uuid)
        self.timestamp = timestamp
        if timestamp is None:
            self.timestamp = now()
        self.payload = payload
        self.parent = parent
        if parent is None:
            self.parent = Genesis
        if self.parent is Genesis:
            self._length = 1
        else:
            self._length = len(self.parent)  # noqa
        self.previous = previous

    def __len__(self):
        return self._length

    def to_dict(self):
        return dict(payload=self.payload, uuid=self.uuid, timestamp=self.timestamp)


class InvalidBranchError(RuntimeError):
    pass


class BranchExistsError(RuntimeError):
    pass


class StepDAG(ABC):
    """
    Directed Acyclic Graph of LinkedSteps
    if no branches, this is a chain
    """
    main_branch = 'main'
    all_branches = 'all'

    def __init__(self):
        self.heads = dict({self.main_branch: Genesis})
        self.__branch_lists = defaultdict(list[LinkedStep])  # cheating for merge

    def __len__(self):
        return len(self.__branch_lists)

    @property
    def main(self):  # longest chain head
        return self.heads[self.main_branch]

    @property
    def size(self):
        return len(self.heads)

    @property
    def temp_name(self):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def add_step(self, step, branch=None):
        """
        Add a link to the given branch (default: main)
        :param step:
        :param branch:
        :return: None
        """
        if branch is None:
            branch = self.main_branch
        if branch not in self.heads:
            raise InvalidBranchError()
        step.parent = self.heads[branch]
        self.heads[branch] = step
        self.__branch_lists[branch].append(step)

    def branch(self, name, step, source=None):
        """
        Create a new named branch, starting with step, diverging from the head of source branch (default: main)
        :param name:
        :param step:
        :param source: name of source branch, or Genesis
        :return: None
        """
        if name in self.heads:
            raise BranchExistsError(name)
        if source is None:
            source = self.main_branch
        if source is Genesis:
            current = Genesis
        elif source not in self.heads:
            raise InvalidBranchError(source)
        else:
            current = self.heads[source]
        self.heads[name] = step
        step.parent = current
        self.__branch_lists[name].append(step)

    def ingest_branch(self, steps, name=None):
        """
        Accept an external branch, as a list fom head to root
        :param steps: list of steps for branch
        :param name: optional name for branch
        :return: name of the branch
        """
        if name is None:
            name = self.temp_name
        self.branch(name, steps[-1], Genesis)
        for step in reversed(steps[:-1]):
            self.add_step(step, name)
        return name

    def diff(self, branch, target=None):
        """
        Find the lowest common ancestor between one branch and another (which defaults to main)
        :param branch:
        :param target:
        :return: common root
        """
        if target is None:
            target = self.main_branch
        if branch not in self.heads:
            raise InvalidBranchError(branch)
        if target not in self.heads:
            raise InvalidBranchError(target)

        shorter = min(len(self.__branch_lists[branch]), len(self.__branch_lists[target]))
        common_root = Genesis
        idx = 0
        for idx in range(0, shorter):
            if self.__branch_lists[branch][idx] != self.__branch_lists[target][idx]:
                if idx > 0:
                    common_root = self.__branch_lists[branch][idx - 1]
                break
        return idx, common_root

    @staticmethod
    def _sort_step_list(steps):
        return sorted(steps, key=lambda x: x.timestamp)

    def merge(self, branch, target=None, keep=False):
        """
        Merge two branches
        :param branch:
        :param target:
        :param keep:
        :return:
        """
        if target is None:
            target = self.main_branch
        if branch not in self.heads:
            raise InvalidBranchError(branch)
        if target not in self.heads:
            raise InvalidBranchError(target)

        idx, common_root = self.diff(branch, target)
        temp = self.temp_name
        self.heads[temp] = common_root
        steps = self.__branch_lists[branch][idx:] + self.__branch_lists[target][idx:]  # noqa
        steps = self._sort_step_list(steps)
        for step in steps:
            self.add_step(step, temp)
        self.heads[target] = self.heads[temp]
        del self.heads[temp]
        if not keep:
            del self.heads[branch]

    def fork(self, head=None):
        if head is None:
            head = self.main_branch
        if head == self.all_branches:
            return deepcopy(self.heads)
        elif head in self.heads:
            return deepcopy(self.heads[head])
        raise InvalidBranchError(head)

    def recite(self, branch=None, root=None):
        """
        Prepare a step list for transmission
        :param branch: branch name
        :param root: first node of sequence
        :return: list of steps
        """
        if branch is None:
            branch = self.main_branch
        if root is None:
            root = Genesis
        step_list = []
        step = self.heads[branch]
        while step != root:
            step_list.append(step)
            step = step.parent
        if root is not Genesis:
            step_list.append(step)
        return step_list

    @abstractmethod
    def _validate(self, branch):
        pass

    def catch_up(self, other_steps):
        """
        Incorporate an external branch
        :param other_steps:
        :return:
        """
        name = self.ingest_branch(other_steps)
        branch_diff = self.recite(name, self.diff(name)[1])
        if self._validate(name):
            self.merge(name)
        return branch_diff

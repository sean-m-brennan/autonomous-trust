import re
import uuid
from collections import Counter, OrderedDict, deque
from enum import Enum

from token_list import TokenList
from data_service import Ident, DataService
from data_eval import distance_hierarchy, exponential_thresholds, linear_thresholds


class Algorithm(str, Enum):
    EXP = 'exp'
    LIN = 'lin'
    CBR = 'cbr'


class DataClient:
    questions: list = []
    answers: dict[int, str] = {}

    def __init__(self, size: int = 20):
        self.memory = deque(maxlen=size)
        self.max_len = 0
        self.registry: dict[Ident, DataService] = dict()

    @property
    def pairwise_distance_matrix(self) -> dict[frozenset[uuid.UUID], float]:
        """pair-wise category distance"""
        pairs: set[frozenset[uuid.UUID]] = set()
        distances: dict[frozenset[uuid.UUID], float] = {}

        for result, whom, _, _ in self.memory:
            if len(result) > self.max_len:
                self.max_len = len(result)
            for result2, peer, _, _ in self.memory:
                if peer == whom:
                    continue
                key = frozenset([whom, peer])
                pairs.add(key)
                if key not in distances:
                    distances[key] = 0
                for cat in result:  # no category preference
                    if cat in result2:
                        dist = abs(result[cat] - result2[cat])
                        distances[key] += dist
                    else:
                        distances[key] += 1.  # max probability
        return distances

    @staticmethod
    def summary(report: list[set[int]]) -> OrderedDict[int, float]:
        a = Counter()
        for observation in report:
            for possibility in observation:
                a[possibility] += 1. / len(observation)

        # predict probabilities (very approximate)
        d = sum(a_j - len(a) for a_j in a.values())
        probabilities = {x: (a_i - 1) / d for x, a_i in a.items()}

        return OrderedDict(sorted(probabilities.items()))

    @classmethod
    def get_help(cls, ask: str):
        def remove_ops(s: str) -> str:
            return re.sub('[%s]' % re.escape('>=%s' % TokenList.greater_equals), '', s.replace(' ', ''))

        machine_ask = remove_ops(ask)
        if machine_ask not in DataClient.questions:
            answer = input('\033[91mQuestion:\033[0m what is the correct sequence from "%s"?  ' % ask).replace(' ', '')
            target_len = len(set(list(machine_ask)))
            machine_answer = remove_ops(answer)
            if len(machine_answer) != target_len:
                print(set(list(machine_ask)))
                raise RuntimeError("That answer is the wrong size (actual %d, expected %d)." %
                                   (len(machine_answer), target_len))
            if machine_answer in machine_ask:
                index = len(cls.questions)
                cls.questions.append(machine_ask)
                cls.answers[index] = answer
                return answer
            raise RuntimeError("That answer makes no sense to me (%s not in %s)." % (machine_answer, machine_ask))

    def register_server(self, whom: Ident, server: DataService):
        self.registry[whom] = server

    def recv_data(self, report: list[set[int]], whom: Ident, time: float) -> tuple[OrderedDict[int, float], Ident, float]:
        """Assumes a categorical distribution is received"""
        result = self.summary(report)
        n = len(result)
        for r in result:
            if r < n:
                result[r] = round(result[r], r)
            else:
                result[r] = round(result[r], r - 1)
        self.memory.append((result, whom, time, len(report)))
        return result, whom, time

    def evaluate(self, which: Algorithm, sensitivity: int, fixed: int = None) -> tuple[list[set[Ident]], list[int]]:
        """Group servers by their data trustworthiness"""
        if which == Algorithm.EXP:
            return self.exponential_pairwise_distance(sensitivity, fixed)
        elif which == Algorithm.LIN:
            return self.linear_pairwise_distance(fixed)
        elif which == Algorithm.CBR:
            self.kb = CBR()
            # FIXME populate CBR
            return self.case_match(fixed)
        else:
            raise RuntimeError('Unknown evaluation algorithm')

    def exponential_pairwise_distance(self, sensitivity: int, fixed: int = None) -> tuple[list[set[Ident]], list[int]]:
        """
        Group peer results into a hierarchy by exponentially increasing distance.
        :param sensitivity: sets initial (lowest) group distance.
        :param fixed: specifies the hierarchy size, but set to None removes empty groups.
        :return: tuple of hierarchy and thresholds
        Works acceptably @ num_nodes=5, sensitivity=4, fixed=3; sensitivity=8 prefers BlindService;
        at large scales, requires large sensitivity;
        greatest weakness: does not scale computationally: O(n^2),
        greatest strength: finds most consistent answers
        """
        return distance_hierarchy(self.pairwise_distance_matrix, exponential_thresholds, self.max_len, sensitivity, fixed)

    def linear_pairwise_distance(self, fixed: int = None) -> tuple[list[set[Ident]], list[int]]:
        """
        Group peer results into a hierarchy by linearly increasing distance.
        :param fixed: specifies the hierarchy size, but set to None removes empty groups.
        :return: tuple of hierarchy and thresholds
        Works less acceptably @ num_nodes=5, sensitivity=4, fixed=3; also not scalable
        """
        return distance_hierarchy(self.pairwise_distance_matrix, linear_thresholds, self.max_len, fixed=fixed)

    def case_match(self, fixed: int = None) -> tuple[list[set[Ident]], list[int]]:
        """
        Group peer results into a hierarchy
        :param fixed: specifies the hierarchy size, but set to None removes empty groups.
        :return: tuple of hierarchy and thresholds
        """
        hierarchy = []
        levels = []
        for result, whom, time, length in self.memory:
            sol = self.kb.process(result)
            # FIXME construct hierarchy
        return hierarchy, levels


class CBR:
    """Stores knowledge graphs"""
    def __init__(self):
        self.memory = dict()

    def process(self, what):
        tried = []
        while True:
            key, known = self.retrieve(what, tried)
            if known is None:
                break
            tried.append(known)
            solution, diff = self.reuse(known, what)
            if solution is not None:
                key, new_known = self.revise(key, known, diff)
                self.retain(key, new_known)
                return solution
        return None

    def retrieve(self, what, tried):
        """Convert situation to key, return knowledge graph"""
        key = what  # FIXME transform
        return key, self.memory[key]

    def reuse(self, graph, what):
        """Apply knowledge graph to situation"""
        return None, None

    def revise(self, key, graph, diff):
        """Apply diff to original knowledge graph, creating a new graph"""
        return key, None

    def retain(self, key, graph):
        self.memory[key] = graph

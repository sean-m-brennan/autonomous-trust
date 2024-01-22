import uuid
from collections import Counter, OrderedDict, deque


class DataClient:
    def __init__(self):
        self.memory = deque(maxlen=20)
        self.max_len = 0

    def recv_data(self, report, whom, time):
        """Assumes a categorical distribution is received"""
        a = Counter()
        for observation in report:
            for possibility in observation:
                a[possibility] += 1/len(observation)

        # predict probabilities (very approximate)
        d = sum(a_j - len(a) for a_j in a.values())
        probabilities = {x: (a_i - 1)/d for x, a_i in a.items()}

        result = OrderedDict(sorted(probabilities.items()))
        self.memory.append((result, whom, time, len(report)))

        n = len(result)
        for r in result:
            if r < n:
                result[r] = round(result[r], r)
            else:
                result[r] = round(result[r], r-1)
        return result, whom, time

    def distance_matrix(self):
        # pair-wise category distance
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

    def evaluate(self, sensitivity=3, absolute=False):
        distances = self.distance_matrix()
        pairs = distances.keys()
        peers = set([p for pair in pairs for p in pair])

        thresholds = []
        groups = []
        idx = 0
        jdx = 0
        prev_dist = 0
        while True:
            if len(groups) < idx + 1:
                groups.append(set())
            max_dist = 0.
            threshold = 2 ** (jdx - sensitivity)
            asc_dist = OrderedDict({k: v for k, v in sorted(distances.items(), key=lambda item: item[1])})
            for key, dist in asc_dist.items():
                dist_dist = abs(dist - prev_dist)
                if dist_dist <= threshold:
                    if dist_dist > max_dist:
                        max_dist = dist_dist
                    flattened = set([p for grp in groups for p in grp])
                    for p in key:
                        if p not in flattened:
                            groups[idx].add(p)
            if absolute or len(groups[idx]) > 0:
                idx += 1
                thresholds.append(threshold)
            prev_dist = max_dist
            if len(set([p for grp in groups for p in grp])) >= len(peers):
                break
            jdx += 1

        return groups, list(map(lambda x: x / self.max_len, thresholds))

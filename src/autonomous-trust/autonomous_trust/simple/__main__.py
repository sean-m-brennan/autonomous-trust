import random

from data_client import DataClient, Algorithm
from data_service import ALL_SERVICES, Ident, DataService


class Network:
    service_classes: list[DataService] = ALL_SERVICES

    def __init__(self, num_nodes: int, levels: int, categories: dict[int, str] = None,
                 algorithm: Algorithm = Algorithm.EXP, randomized: bool = False):
        self.services = []
        self.clients = []
        self.num_nodes = num_nodes
        self.levels = levels
        self.algorithm = algorithm
        self.rand_svc = randomized
        if categories is None:
            categories = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}

        for i in range(num_nodes):
            srv = self.service_classes[i % len(self.service_classes)](categories)
            self.services.append(srv)
            self.clients.append(DataClient(num_nodes))

    def _choose_service(self, idx: int, rnd: int) -> DataService:
        if self.rand_svc:
            jdx = random.randint(0, len(self.services)-2)
            if jdx >= idx:
                jdx += 1
        else:  # round-robin
            jdx = (rnd + 1) % len(self.services)
        return self.services[jdx]

    def get_ground_truth(self, sensitivity: int, num_rounds: int = None) -> list[list[tuple[set[Ident], float]]]:
        if num_rounds is None:
            num_rounds = self.num_nodes

        # mutually acquire data
        latest = [[]] * self.num_nodes
        for rnd in range(num_rounds):
            for idx, client in enumerate(self.clients):
                service = self._choose_service(idx, rnd)
                client.register_server(service.ident, service)
                client.recv_data(*service.send_report())

        # evaluate collected data
        for idx, client in enumerate(self.clients):
            hierarchy, levels = client.evaluate(self.algorithm, sensitivity, self.levels)
            latest[idx] = list(zip(levels, hierarchy))
        return latest


if __name__ == '__main__':
    print('Five')
    conclusions = Network(num_nodes=6, levels=5, algorithm=Algorithm.EXP).get_ground_truth(4)
    for index, result in enumerate(conclusions):
        print(index, result)

    print('Ten')
    conclusions = Network(num_nodes=10, levels=5, algorithm=Algorithm.EXP).get_ground_truth(8)
    for index, result in enumerate(conclusions):
        print(index, result)

    print('Twenty')
    conclusions = Network(num_nodes=20, levels=5, algorithm=Algorithm.EXP).get_ground_truth(16)
    for index, result in enumerate(conclusions):
        print(index, result)

    print('Fifty')
    conclusions = Network(num_nodes=50, levels=5, algorithm=Algorithm.EXP).get_ground_truth(24)
    for index, result in enumerate(conclusions):
        print(index, result)

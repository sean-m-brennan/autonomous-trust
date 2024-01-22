import random
from collections import namedtuple

from data_client import DataClient
from data_service import ExactService, BlindService, FaultyService, BiasedService


Node = namedtuple('Node', ['client', 'service'])


def simulate(num_rounds=2, num_nodes=10):
    service_classes = [ExactService, BlindService, FaultyService, BiasedService]
    services = []
    nodes = []
    for i in range(num_nodes):
        srv = service_classes[i % len(service_classes)]()
        services.append(srv)
        nodes.append(Node(DataClient(), srv))

    latest = [[]] * num_nodes
    for i in range(num_rounds):
        for idx, node in enumerate(nodes):
            client, service = node
            # randomized
            jdx = random.randint(0, len(services)-2)
            if jdx >= idx:
                jdx += 1
            # determinate
            jdx = (i + 1) % len(services)

            client.recv_data(*services[jdx].send())
            hierarchy, levels = client.evaluate(absolute=True)
            latest[idx] = hierarchy
    for idx in range(num_nodes):
        print(idx, latest[idx])


if __name__ == '__main__':
    simulate()

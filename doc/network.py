# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import math
from itertools import combinations, groupby
import networkx as nx
import random
import matplotlib.pyplot as plt


def gnp_random_connected_graph(n, p):
    edges = combinations(range(1, n + 1), 2)
    G = nx.Graph()
    G.add_nodes_from(range(1, n + 1))
    if p <= 0:
        return G
    if p >= 1:
        return nx.complete_graph(n, create_using=G)
    min_affinity = 10
    max_affinity = 100
    for _, node_edges in groupby(edges, key=lambda x: x[0]):
        node_edges = list(node_edges)
        random_edge = random.choice(node_edges)
        G.add_edge(*random_edge, affinity=random.randint(min_affinity, max_affinity))
        for edge in node_edges:
            if random.random() < p:
                G.add_edge(*edge, affinity=random.randint(min_affinity, max_affinity))
    return G


def plot_graph(G):
    fig = plt.figure(figsize=(8, 8))
    pos = nx.spring_layout(G, weight='affinity')
    ax = fig.gca()
    ax.axis('equal')

    for idx in pos:
        max_dist = 0
        min_dist = 500
        avg_dist = 0
        num_edges = 0
        for edge in G.edges:
            if idx in edge:
                pt1 = pos[edge[0]]
                pt2 = pos[edge[1]]
                dist = math.sqrt((pt1[0] - pt2[0]) ** 2 + (pt1[1] - pt2[1]) ** 2)
                avg_dist += dist
                if dist > max_dist:
                    max_dist = dist
                if dist < min_dist:
                    min_dist = dist
                num_edges += 1
        avg_dist = avg_dist / num_edges
        circle1 = plt.Circle(pos[idx], min_dist, color='teal', fill=False)
        circle2 = plt.Circle(pos[idx], avg_dist, color='blue', fill=False)
        circle3 = plt.Circle(pos[idx], max_dist, color='lightblue', fill=False)
        ax.add_patch(circle3)
        ax.add_patch(circle2)
        ax.add_patch(circle1)

    nx.draw(G, pos,
            node_color='darkblue',
            font_color='white',
            with_labels=True,
            node_size=500)
    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    nodes = 20
    edge_prob = 0.2
    G = gnp_random_connected_graph(nodes, edge_prob)
    plot_graph(G)

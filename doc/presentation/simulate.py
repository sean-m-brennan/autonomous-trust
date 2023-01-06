#!/usr/bin/env python3

import asyncio
import json
import random

import quart
import networkx as nx


port = 8000
debug = False


class NetGraph():
    initial_delay = 5000  # millisec #FIXME 1 sec when triggered by slide

    def __init__(self, m1, m2):
        self.m1 = m1
        self.m2 = m2
        self._reset()

    def _reset(self):
        self.G = nx.barbell_graph(self.m1, self.m2)
        self.change_type = None
        self.initialized = False
        self.next_change = self.initial_delay
        for n in self.node_ids:
            self.G.nodes[n]["name"] = n
        self._record_state()

    @property
    def node_ids(self):
        return list([n for n in self.G])

    @property
    def max_node_id(self):
        return max(self.node_ids)

    def _record_state(self):
        previous_state = self._to_dict(False)
        self.previous_nodes = previous_state['nodes']
        self.previous_links = previous_state['links']

    def _random_node(self, exclude=None):
        idx = random.randint(0, len(self.node_ids)-1)
        if idx == exclude:
            if exclude == 0:
                idx += 1
            else:
                idx -= 1
        return self.node_ids[idx]

    def _random_pair(self):
        n1 = self._random_node()
        n2 = self._random_node(n1)
        return n1, n2

    def change(self):
        r = random.randint(1, 100)
        if r < 20:
            node_num = self.max_node_id + 1
            self.change_type = 'add'
            self.G.add_node(node_num)
        elif 20 < r < 70:
            self.change_type = 'add'
            edge = self._random_pair()
            while self.G.has_edge(*edge):
                edge = self._random_pair()
            self.G.add_edge(*edge)
        elif r > 95:
            node_num = self._random_node()
            self.change_type = 'remove'
            self.G.remove_node(node_num)
        elif 70 < r < 95:
            self.change_type = 'remove'
            edge = self._random_pair()
            while not self.G.has_edge(*edge):
                edge = self._random_pair()
            self.G.remove_edge(*edge)
        for n in [n for n in self.G]:
            self.G.nodes[n]["name"] = n
        self.next_change = random.randint(1, 2000)

    def renew(self):
        self._reset()

    def get_update(self):
        if self.initialized:
            self.change()
        if debug:
            print("Serve %sgraph data: %d nodes, %d links" %
                  ("full " if not self.initialized else "",
                   len(self._to_dict()["nodes"]),
                   len(self._to_dict()["links"])))
        data = str(self)
        self._record_state()
        self.initialized = True
        return self.next_change / 1000.0, data

        
    def nodeset_diff(self, s1, s2):
        node_diff = set([n['id'] for n in s1]) - set([n['id'] for n in s2])
        result = []
        for n in node_diff:
            for d in s1 + s2:
                if d['id'] == n:
                    result.append(d)
                    break
        return result

    def edgeset_diff(self, s1, s2):
        edge_diff = set([(e['source'], e['target']) for e in s1]) - set([(e['source'], e['target']) for e in s2])
        result = []
        for e in edge_diff:
            for d in s1 + s2:
                if d['source'] == e[0] and d['target'] == e[1]:
                    result.append(d)
                    break
        return result

    def _to_dict(self, track_change=True):
        # node-link format to serialize
        data_obj = nx.json_graph.node_link_data(self.G)
        if track_change and self.change_type:
            data_obj['type'] = self.change_type
            if self.change_type == 'add':
                data_obj['nodes'] = self.nodeset_diff(data_obj['nodes'], self.previous_nodes)
                data_obj['links'] = self.edgeset_diff(data_obj['links'], self.previous_links)
            elif self.change_type == 'remove':
                data_obj['nodes'] = self.nodeset_diff(self.previous_nodes, data_obj['nodes'])
                data_obj['links'] = self.edgeset_diff(self.previous_links, data_obj['links'])
        return data_obj

    def __str__(self):
        return json.dumps(self._to_dict())

    def to_file(self, filename):
        json.dump(self._to_dict(False), open(filename, "w"))


##############################


appq = quart.Quart(__name__, static_url_path='', static_folder=".")


@appq.route("/")
async def presentation():
    return await quart.send_from_directory(".", "index.html")


@appq.websocket('/ws')
async def ws():
    graph = NetGraph(6, 0)  # two bells of m1 nodes, connected by m2 nodes
    while True:
        msg = await quart.websocket.receive()
        seconds, data = graph.get_update()
        await quart.websocket.send(data)
        await asyncio.sleep(seconds)


appq.run(port=port)

import os
import random


def random_name(sep='_', cap=False):
    d = os.path.dirname(__file__)
    adj_file = os.path.join(d, 'adjectives.txt')
    with open(adj_file, 'r') as a:
        adj_list = a.read().strip().split('\n')
    nm_file = os.path.join(d, 'names.txt')
    with open(nm_file, 'r') as n:
        name_list = n.read().strip().split('\n')
    a_idx = random.randint(0, len(adj_list) - 1)
    n_idx = random.randint(0, len(name_list) - 1)
    pre = adj_list[a_idx]
    post = name_list[n_idx]
    if cap:
        pre = pre.capitalize()
        post = post.capitalize()
    return pre + sep + post

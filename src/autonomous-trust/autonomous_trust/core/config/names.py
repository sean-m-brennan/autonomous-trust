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

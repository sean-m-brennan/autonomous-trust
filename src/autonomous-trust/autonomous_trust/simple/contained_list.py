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

class ContainedList:
    """Allows a class that contains a list to act like that list"""
    def __init__(self, lst: list):
        self.lst = lst

    def __len__(self):
        return self.lst.__len__()

    def __getitem__(self, key):
        return self.lst.__getitem__(key)

    def __setitem__(self, key, value):
        return self.lst.__setitem__(key, value)

    def __delitem__(self, key):
        return self.lst.__delitem__(key)

    def __iter__(self):
        return self.lst.__iter__()

    def __reversed__(self):
        return self.lst.__reversed__()

    def __contains__(self, item):
        return self.lst.__contains__(item)

    def __add__(self, other):
        return self.lst.__add__(other)

    def __iadd__(self, other):
        return self.lst.__iadd__(other)

    def __mul__(self, other):
        return self.lst.__mul__(other)

    def __rmul__(self, other):
        return self.lst.__rmul__(other)

    def __imul__(self, other):
        return self.lst.__imul__(other)

    def append(self, item):
        return self.lst.append(item)

    def insert(self, index, item):
        return self.lst.insert(index, item)

    def pop(self, index):
        return self.lst.pop(index)

    def remove(self, item):
        return self.lst.remove(item)

    def count(self, item):
        return self.lst.count(item)

    def index(self, item):
        return self.lst.index(item)

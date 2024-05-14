import json
import math
from decimal import Decimal
from typing import Union, Callable, Iterable

from majority import majority
from token_list import TokenList, TokenStruct, TokenListClass
from data_client import DataClient
from data_service import ALL_SERVICES


class IncompleteSamplingException(RuntimeError):
    def __init__(self, cat: 'Category'):
        self.category = cat

    def __str__(self):
        return '%s: incomplete sampling error (category size %d vs expected %d)' % \
            (self.category.name, len(self.category.tokens.flatten()), len(self.category.struct))


class SemanticMismatchException(RuntimeError):
    def __init__(self, cat: 'Category', seq: str):
        self.category = cat
        self.sequence = seq

    def __str__(self):
        return '%s: semantic mismatch error (sequence %s vs expected %s)' % \
            (self.category.name, self.category.sentence, self.sequence)


def frexp(number, base_two=True):
    if base_two:
        return math.frexp(number)
    (sign, digits, exponent) = Decimal(number).as_tuple()
    f_exp = len(digits) + exponent - 1
    return Decimal(number).scaleb(-f_exp).normalize(), f_exp


class Category:
    __create_key = object()
    struct: TokenStruct = None
    token_class: TokenListClass = None
    parent: 'CategoryClass' = None

    @classmethod
    def from_token_class(cls, parent: 'CategoryClass', token_class: TokenListClass, srv_class: type, sensitivity: int = 0):
        cls.token_class = token_class
        cls.struct = token_class.struct
        cls.parent = parent
        return cls(cls.__create_key, srv_class, sensitivity)

    @classmethod
    def from_struct(cls, parent: 'CategoryClass', struct: TokenStruct, srv_class: type, sensitivity: int = 0):
        cls.token_class = TokenListClass(struct)
        cls.struct = struct
        cls.parent = parent
        return cls(cls.__create_key, srv_class, sensitivity)

    def __init__(self, key, srv_class: type, sensitivity: int = 0):
        if key is not Category.__create_key:
            raise RuntimeError("Category objects must be created using a CategoryClass object")
        self.klass = srv_class
        self.name = srv_class.__name__
        self.srv = srv_class(self.struct)
        self.sensitivity = sensitivity
        self.summary = DataClient.summary(self.srv.report())

        desc = list(reversed(sorted(self.summary.items(), key=lambda item: item[1])))
        self.tokens = self.token_class.from_freq(desc, sensitivity)
        self.sentence = self.tokens.sentence
        self.phrases = self.tokens.phrases
        self.alt_sentences = self.tokens.alt_sentences

    def contains_sequence(self, seq: str) -> bool:
        if self.phrases is None:
            raise IncompleteSamplingException(self)
        for phrase in self.phrases:
            if seq in phrase:
                return True
        return False

    @classmethod
    def longest_common_sequence(cls, categories: list['Category'], proportion: Callable[[Iterable], bool] = all) -> str:
        return cls.parent.longest_common_sequence([c.tokens for c in categories], proportion)

    @classmethod
    def combine(cls, categories: list['Category']) -> str:
        return cls.parent.combine([c.tokens for c in categories])

    @classmethod
    def distances(cls, categories: list['Category'], base_two: bool = False) -> dict[str, dict[str, int]]:
        return cls.parent.distances(categories, base_two)

    @classmethod
    def match(cls, token_lists: list[TokenList], categories: list['Category']):
        return cls.parent.match(token_lists, categories)


class CategoryClass:
    """Creates consistent Category objects given a TokenStruct or TokenListClass;
    also shorthand access for class methods"""
    def __init__(self, token_class: TokenListClass = None, struct: TokenStruct = None):
        self.token_class = None
        self.struct = None
        if token_class is not None:
            self.token_class = token_class
            self.struct = self.token_class.struct
        elif struct is not None:
            self.struct = struct
            self.token_class = TokenListClass(struct)
        else:
            raise RuntimeError('CategoryClass must be constructed with one of: TokenListClass or TokenStruct')

    def __call__(self, srv_class: type, sensitivity: int = 0):
        if self.token_class:
            return Category.from_token_class(self, self.token_class, srv_class, sensitivity)
        else:
            return Category.from_struct(self, self.struct, srv_class, sensitivity)

    def longest_common_sequence(self, categories: list[Category], proportion: Callable[[Iterable], bool] = all) -> str:
        return self.token_class.longest_common_sequence([c.tokens for c in categories], proportion).join()

    def combine(self, categories: list[Category]) -> str:
        return self.token_class.combine([c.tokens for c in categories])

    def distances(self, categories: list[Category], base_two: bool = False) -> dict[str, dict[str, int]]:
        dist = {}
        for cat in categories:
            dist[cat.name] = {}
            srv_class = cat.klass
            # get new, but self-similar category instance; shortcut to variance
            self_diff = self(srv_class, cat.sensitivity).summary
            close = sum(map(lambda kv: abs(kv[1] - self_diff[kv[0]]), cat.summary.items()))
            close_enough = frexp(close, base_two)[1]
            for srv_diff in ALL_SERVICES:
                if srv_class == srv_diff:
                    continue
                alt = self(srv_diff, cat.sensitivity)
                far = 0
                for key, value in alt.summary.items():
                    try:
                        far += abs(value - cat.summary[key])
                    except KeyError:
                        pass
                dist[cat.name][alt.name] = frexp(far, base_two)[1] - close_enough
        return dist

    def match(self, token_lists: list[TokenList], categories: list['Category']):
        matches = []
        for t_list in token_lists:
            for cat in categories:
                if str(cat.tokens) == str(t_list):
                    matches.append(cat)
                    break
        return matches

    def all_categories(self, sensitivity) -> list['Category']:
        categories = []
        for srvClass in ALL_SERVICES:
            cat = self(srvClass, sensitivity)
            categories.append(cat)
        return categories

    def independent_validation(self, category: Category, tolerance: int = 1e-2) -> TokenList:
        observations = category.srv.send_data()
        possible = set(observations)
        count_map: dict[str, int] = {}
        for idx in possible:
            cat_id = category.struct[idx]
            count_map[cat_id] = observations.count(idx)
        cap_sort = sorted(count_map.items(), key=lambda item: item[1], reverse=True)
        tokens: TokenList = self.token_class()
        initial = True
        idx = 1
        while idx < len(cap_sort):
            prev = cap_sort[idx - 1]
            cur = cap_sort[idx]
            if math.isclose(prev[1], cur[1], rel_tol=tolerance):
                if initial:
                    tokens.append([])
                    tokens[-1].append(prev[0])
                    initial = False
                    idx += 1
            else:
                tokens.append(prev[0])
                initial = True
            if idx == len(cap_sort):
                tokens[-1].append(cur[0])
            idx += 1
            if idx == len(cap_sort):
                tokens.append(cur[0])
        return tokens

    def constrain_categories(self, categories: list[Category], debug: Union[int, bool] = 0) -> list[Category]:
        if debug is True:
            debug = 1
        if debug > 1:
            for category in categories:
                print('%s: %s' % (category.name, json.dumps(category.summary)))

        seq = self.longest_common_sequence(categories, majority)
        distances = self.distances(categories)
        selected_cats = []
        for category in categories:
            try:
                if not category.contains_sequence(seq):
                    if debug:
                        print(SemanticMismatchException(category, seq))
                    continue
            except IncompleteSamplingException as err:
                if debug:
                    print(err)
                continue
            selected_cats.append(category)
            if debug:
                print('%s: \033[94m%s\033[0m  original: %s  consistency = %s' %
                      (category.name, seq, category.sentence, sum(category.summary.values())))
                if debug > 1:
                    for key, val in distances[category.name].items():
                        print('  distance to %s: %d' % (key, val))
        if debug:
            print('Combination of all %d considered sequences: %s' % (len(selected_cats), self.combine(selected_cats)))

        if len(selected_cats) > 1:
            # FIXME determine doubt
            valid = []
            for cat in selected_cats:  # minimize categories to avoid over-determination (and extra work!)
                tokens = self.independent_validation(cat)  # FIXME only those that are doubtful
                valid.append(tokens)
            matched = list(set(Category.match(valid, categories)))
            if len(matched) > 0:
                selected_cats = matched
            if debug:
                print('Narrowed down to %d: %s' % (len(selected_cats), self.combine(selected_cats)))

        if len(selected_cats) != 1:  # last resort: ask the user
            answer = DataClient.get_help(self.combine(selected_cats))
            if debug:
                print('Boss says %s' % ' '.join(list(answer)))
            selected_cats = []
            for category in categories:
                alt = category.alt_sentences
                if alt is not None and answer in [s.replace(' ', '') for s in alt]:
                    selected_cats.append(category)

        if debug:
            print('Using %s: \033[92m%s\033[0m as ground truth' % (selected_cats[0].name, selected_cats[0].sentence))
        return selected_cats


##############################


def main():
    # Assumption: most people (peers) are good - just need the majority to be consistent enough; *efficient*
    # Counter-assumption: most people (peers) are bad - therefore must find the best data heuristically
    debug = True
    cat_struct = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
    klass = CategoryClass(struct=cat_struct)
    cats = klass.all_categories(1)
    klass.constrain_categories(cats, debug)


if __name__ == '__main__':
    main()

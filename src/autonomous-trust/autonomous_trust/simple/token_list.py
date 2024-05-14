from difflib import SequenceMatcher
from typing import Union, Callable, Iterable

from contained_list import ContainedList
from majority import majority


TokenStruct = dict[int, str]

TokenFreq = list[tuple[int, float]]


class TokenListMeta(type):
    def __new__(mcs, name, bases, namespace, **kwargs):
        return super().__new__(mcs, name, bases, namespace)

    def __init__(cls, name, bases, namespace, struct):
        super().__init__(name, bases, namespace)
        cls.struct = struct


class TokenList(ContainedList):
    __create_key = object()
    struct: TokenStruct = None
    parent: 'TokenListClass' = None
    greater_equals = '≥'

    def __init__(self, key, tokens: list[Union[str, list[str]]] = None):
        if key is not TokenList.__create_key:
            raise RuntimeError("TokenList objects must be created using a TokenListClass object")
        if tokens is None:
            tokens = []
        super().__init__(tokens)
        self.tokens = tokens

    @classmethod
    def from_struct(cls, parent: 'TokenListClass', struct: TokenStruct, tokens: list[Union[str, list[str]]] = None) -> 'TokenList':
        cls.struct = struct
        cls.parent = parent
        return TokenList(cls.__create_key, tokens)

    @classmethod
    def from_freq(cls, parent: 'TokenListClass', struct: TokenStruct, descriptor: TokenFreq, sensitivity: int = 0) -> 'TokenList':
        cls.struct = struct
        cls.parent = parent
        tokens = []
        initial = True
        idx = 0
        while idx < len(descriptor):
            op = TokenList.parse_operator(descriptor, idx, sensitivity)
            if op == '=':
                if initial:
                    tokens.append([])
                    tokens[-1].append(descriptor[idx][0])
                    initial = False
                    idx += 1
                tokens[-1].append(descriptor[idx][0])
            elif op == '>':
                tokens.append(descriptor[idx][0])
                initial = True
            else:
                if descriptor[idx][0] != '':
                    tokens.append(descriptor[idx][0])
            idx += 1
        return TokenList(cls.__create_key, tokens)

    @classmethod
    def rectify_string(cls, sentence: Union[str, bytes]) -> str:
        sentence = sentence.replace(' ', '')
        s_copy = []
        idx = 0
        while idx < len(sentence):
            if sentence[idx:idx+2] == '>=' or sentence[idx:idx+2] == '=>':
                s_copy.append(' %s ' % cls.greater_equals)
                idx += 1
            elif sentence[idx] == '>' or sentence[idx] == '=' or sentence[idx] == cls.greater_equals:
                s_copy.append(' %s ' % sentence[idx])
            else:
                s_copy.append(sentence[idx])
            idx += 1
        return ''.join(s_copy)

    @classmethod
    def split_multistring(cls, sentence: str) -> list[str]:
        exp = sentence.count(cls.greater_equals)
        if exp < 1:
            return [sentence]
        count = (2 ** exp) // 2
        # find 1st cls.greater_equals, split in half, first are '>', second are'='
        # recurse
        pre, post = sentence.split(cls.greater_equals, 1)
        end = cls.split_multistring(post) * 2
        result = [pre + '>'] * count + [pre + '='] * count
        for idx in range(len(result)):
            result[idx] += end[idx]
        return result

    @classmethod
    def parse_multi(cls, parent: 'TokenListClass', struct: TokenStruct, sentence: str) -> list['TokenList']:
        sentence = cls.rectify_string(sentence)
        lst = []
        for sub in cls.split_multistring(sentence):
            lst.append(cls.__parse(parent, struct, sub))
        return lst

    @classmethod
    def parse(cls, parent: 'TokenListClass', struct: TokenStruct, sentence: str) -> 'TokenList':
        sentence = cls.rectify_string(sentence)
        return cls.__parse(parent, struct, sentence)

    @classmethod
    def __parse(cls, parent: 'TokenListClass', struct: TokenStruct, sentence: str) -> 'TokenList':
        cls.struct = struct
        cls.parent = parent

        op_tokens = sentence.split()
        tokens = []
        idx = 0
        sublist = None
        prev = op_tokens[0]
        while idx < len(op_tokens):
            tok = op_tokens[idx]
            if idx == 0:
                pass
            elif op_tokens[idx] == cls.greater_equals:
                raise RuntimeError('Combination operators (%s) are invalid for TokenList' % cls.greater_equals)
            elif op_tokens[idx] == '=':
                if sublist:
                    sublist.append(prev)
                else:
                    sublist = [prev]
                    tokens.append(sublist)
            elif op_tokens[idx] == '>':
                if sublist:
                    sublist.append(prev)
                    sublist = None
                else:
                    tokens.append(prev)
            else:
                prev = op_tokens[idx]
            idx += 1
            if idx == len(op_tokens):
                if sublist:
                    sublist.append(prev)
                else:
                    tokens.append(prev)
        return TokenList(cls.__create_key, tokens)

    def __str__(self):
        return self.join()

    @property
    def sentence(self):
        sentence = ''
        for i, t in enumerate(self.tokens):
            if not isinstance(t, str):  # i.e. list
                sentence += ' = '.join(t)
                if i < len(self.tokens) - 1:
                    sentence += ' > '
            elif i < len(self.tokens) - 1:
                sentence += '%s > ' % t
            else:
                sentence += t
        return sentence

    @property
    def phrases(self):
        return self.__alt(True)

    @property
    def alt_sentences(self):
        return self.__alt(False)

    def __alt(self, phrase: bool):
        if len(self.flatten()) < len(self.struct):
            return None
        alts = ['']
        for i, t in enumerate(self.tokens):
            orig_len = len(alts)
            if not isinstance(t, str):  # list
                alts *= len(t)
                tdx = 0
                for jdx in range(len(alts)):
                    alts[jdx] += t[tdx]
                    if phrase:
                        if (jdx % (len(alts) // orig_len)) == 0:
                            tdx += 1
                    else:
                        for kdx in range(len(t)):
                            if kdx != tdx:
                                alts[jdx] += ' = '
                                alts[jdx] += t[kdx]
                        tdx += 1
                    if i < len(self.tokens) - 1:
                        alts[jdx] += ' > '
            elif i < len(self.tokens) - 1:
                for idx in range(len(alts)):
                    alts[idx] += '%s > ' % t
            else:
                for idx in range(len(alts)):
                    alts[idx] += t
        return alts

    def join(self) -> str:
        t_list = []
        for token in self.tokens:
            if isinstance(token, list):
                token = ' = '.join(token)
            t_list.append(token)
        return ' > '.join(t_list)

    def flatten(self):
        flat = []
        for item in self.tokens:
            if isinstance(item, list):
                for sub_item in item:
                    flat.append(sub_item)
            else:
                flat.append(item)
        return flat

    @staticmethod
    def parse_operator(desc: TokenFreq, index: int, sensitivity: int) -> str:
        freqs = list(map(lambda x: x[1], desc))
        op: str = ''
        if index + 1 < len(freqs):
            # for more accurate comparisons, convert to strings instead of rounding
            fr1, fr2 = str(freqs[index]), str(freqs[index + 1])
            sm = SequenceMatcher(None, fr1, fr2)
            match = sm.find_longest_match(0, len(fr1), 0, len(fr2))
            sequence = fr1[match.a: match.a + match.size]
            common = sequence[sequence.find('.'):]
            if len(common) > sensitivity:
                op = '='
            elif freqs[index] > freqs[index + 1]:
                op = '>'
        return op

    @classmethod
    def expand(cls, token_list: list['TokenList']) -> list['TokenList']:
        """Expand token list nesting into separate lists"""
        return cls.parent.expand(token_list)

    @classmethod
    def longest_common_sequence(cls, token_list: list['TokenList']) -> 'TokenList':
        """Find the longest common sequence present in the majority of token lists"""
        return cls.parent.longest_common_sequence(token_list)

    @classmethod
    def combine(cls, token_list: list['TokenList']) -> str:
        return cls.parent.combine(token_list)


class TokenListClass:
    def __init__(self, struct: TokenStruct):
        self.struct = struct

    def __call__(self, tokens: list[Union[str, list[str]]] = None):
        return TokenList.from_struct(self, self.struct, tokens)

    def from_freq(self, descriptor: TokenFreq, sensitivity: int = 0):
        return TokenList.from_freq(self, self.struct, descriptor, sensitivity)

    def parse(self, sentence: str) -> TokenList:
        return TokenList.parse(self, self.struct, sentence)

    def parse_multi(self, sentence: str) -> list[TokenList]:
        return TokenList.parse_multi(self, self.struct, sentence)

    def expand(self, token_list: list[TokenList]) -> list[TokenList]:
        """Expand token list nesting into separate lists"""
        delim = '\0'
        expanded: list[TokenList] = []
        for t_list in token_list:
            targets = ['']
            for token in t_list:
                if isinstance(token, list):
                    targets *= len(token)
                    for idx, sub_token in enumerate(token):
                        targets[idx] += delim + sub_token
                else:
                    for idx in range(len(targets)):
                        targets[idx] += delim + token
            expanded.append(TokenList.from_struct(self, self.struct, [lst.split(delim)[1:] for lst in targets]))
        return expanded

    def longest_common_sequence(self, token_list: list[TokenList], proportion: Callable[[Iterable], bool] = all) -> TokenList:
        """Find the longest common sequence present in the majority of token lists"""
        target = self.__common_sequence(token_list, proportion)
        if len(target) == 0 and proportion is not all:
            target = self.__common_sequence(token_list, majority)  # fallback
        return TokenList.from_struct(self, self.struct, target)

    def __common_sequence(self, token_list: list[TokenList], proportion: Callable[[Iterable], bool]) -> list:
        delim = '\0'
        target = []
        token_seqs = self.expand(token_list)
        sentences = [[delim.join(s) for s in seq] for seq in token_seqs]
        for idx, seq in enumerate(token_seqs):
            if idx == 0:
                continue
            for tokens in seq:
                for prev in token_seqs[idx - 1]:
                    prev_str = delim.join(prev)
                    cur_str = delim.join(tokens)
                    sm = SequenceMatcher(None, prev_str, cur_str)
                    match = sm.find_longest_match(0, len(prev_str), 0, len(cur_str))
                    sequence = prev_str[match.a: match.a + match.size]
                    enough = proportion([any([sequence in s for s in sl]) for sl in sentences])
                    sequence = list(filter(''.__ne__, sequence.split(delim)))
                    if enough and len(sequence) > 0 and len(sequence) > len(target):
                        target = sequence
        return target

    def combine(self, token_list: list[TokenList]) -> str:
        if len(token_list) == 1:
            return token_list[0].join()

        def track_token(tok: Union[str, list[str]], was_seen: bool, common: TokenList,
                        track: list[str], eq: list[str], gt: list[str]):
            if isinstance(tok, list):
                for element in tok:
                    if element not in common:
                        eq.append(element)
                        if element not in track:
                            track.append(element)
                    else:
                        was_seen = True  # common seq was encountered, go to next phase
            else:
                if tok not in common:
                    gt.append(tok)
                    if tok not in track:
                        track.append(tok)
                else:
                    was_seen = True
            return was_seen

        core = self.longest_common_sequence(token_list)
        pre, pre_eq, pre_gt = [], [], []
        post, post_eq, post_gt = [], [], []
        for sentence in token_list:
            seen = False
            for token in sentence:
                if not seen:
                    #seen = track_token(token, seen, core, pre, pre_eq, pre_gt)
                    if isinstance(token, list):
                        for elt in token:
                            if elt not in core:
                                pre_eq.append(elt)
                                if elt not in pre:
                                    pre.append(elt)
                            else:
                                seen = True  # core was encountered, go to next phase
                    else:
                        if token not in core:
                            pre_gt.append(token)
                            if token not in pre:
                                pre.append(token)
                        else:
                            seen = True
                else:
                    #track_token(token, seen, core, post, post_eq, post_gt)
                    if isinstance(token, list):
                        for elt in token:
                            if elt not in core:
                                post_eq.append(elt)
                                if elt not in post:
                                    post.append(elt)
                    else:
                        if token not in core:
                            post_gt.append(token)
                            if token not in post:
                                post.append(token)

        pre_s = ''
        for token in set(pre):
            op = TokenList.greater_equals if token in pre_eq and token in pre_gt else '>' if token in pre_gt else '='
            pre_s += '%s %s ' % (token, op)
        post_s = ''
        for token in set(post):
            op = TokenList.greater_equals if token in post_eq and token in post_gt else '>' if token in post_gt else '='
            post_s += ' %s %s' % (op, token)
        return pre_s + ' > '.join(core) + post_s

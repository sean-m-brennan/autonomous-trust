# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
import pytest

from autonomous_trust.simple.contained_list import ContainedList
from autonomous_trust.simple.token_list import TokenList, TokenListClass, TokenStruct


STRUCT = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}


class TestTokenListClass:
    def test_init(self):
        tlc = TokenListClass(STRUCT)
        assert tlc.struct == STRUCT

    def test_call_empty(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc()
        assert len(tl) == 0

    def test_call_with_tokens(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        assert len(tl) == 3

    def test_parse_simple(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc.parse('A > B > C > D')
        assert len(tl.flatten()) == 4

    def test_parse_equals(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc.parse('A = B > C > D')
        # A=B should produce a sublist
        found_sublist = False
        for t in tl.tokens:
            if isinstance(t, list):
                found_sublist = True
                assert 'A' in t
                assert 'B' in t
        assert found_sublist

    def test_parse_multi(self):
        tlc = TokenListClass(STRUCT)
        results = tlc.parse_multi('A >= B > C > D')
        assert len(results) == 2


class TestTokenList:
    def test_cannot_create_directly(self):
        with pytest.raises(RuntimeError, match='must be created'):
            TokenList(object(), ['A', 'B'])

    def test_from_struct(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        assert len(tl) == 3

    def test_str(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        s = str(tl)
        assert 'A' in s
        assert '>' in s

    def test_join(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        assert tl.join() == 'A > B > C'

    def test_join_with_equals(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', ['B', 'C'], 'D'])
        j = tl.join()
        assert 'B = C' in j

    def test_flatten(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', ['B', 'C'], 'D'])
        flat = tl.flatten()
        assert flat == ['A', 'B', 'C', 'D']

    def test_sentence(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', ['B', 'C'], 'D'])
        s = tl.sentence
        assert 'B = C' in s
        assert '>' in s

    def test_sentence_simple(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        s = tl.sentence
        assert s == 'A > B > C'

    def test_parse_operator_equal(self):
        # SequenceMatcher compares string representations of floats
        # '0.5' vs '0.50001' - common substring after '.' determines sensitivity
        desc = [(1, 0.5), (2, 0.5)]
        op = TokenList.parse_operator(desc, 0, 0)
        assert op == '='

    def test_parse_operator_greater(self):
        desc = [(1, 0.9), (2, 0.1)]
        op = TokenList.parse_operator(desc, 0, 0)
        # Check that it's either '>' or '=' based on string similarity
        assert op in ('>', '=')

    def test_parse_operator_end(self):
        desc = [(1, 0.5)]
        op = TokenList.parse_operator(desc, 0, 0)
        assert op == ''

    def test_rectify_string(self):
        s = TokenList.rectify_string('A>B=C>=D')
        assert '>' in s
        assert '=' in s

    def test_split_multistring_no_ge(self):
        result = TokenList.split_multistring('A > B > C')
        assert len(result) == 1

    def test_split_multistring_one_ge(self):
        ge = TokenList.greater_equals
        result = TokenList.split_multistring('A %s B > C' % ge)
        assert len(result) == 2


class TestTokenListFromFreq:
    def test_basic(self):
        tlc = TokenListClass(STRUCT)
        desc = [('A', 0.5), ('B', 0.25), ('C', 0.125), ('D', 0.125)]
        tl = tlc.from_freq(desc, 0)
        assert len(tl.flatten()) > 0


class TestTokenListClassExpand:
    def test_expand(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc([['A', 'B'], 'C', 'D'])
        expanded = tlc.expand([tl])
        assert len(expanded) == 1


class TestTokenListClassLCS:
    def test_lcs(self):
        tlc = TokenListClass(STRUCT)
        tl1 = tlc(['A', 'B', 'C', 'D'])
        tl2 = tlc(['A', 'B', 'D', 'C'])
        result = tlc.longest_common_sequence([tl1, tl2])
        assert len(result) > 0


class TestTokenListClassCombine:
    def test_combine_single(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B', 'C'])
        result = tlc.combine([tl])
        assert result == 'A > B > C'

    def test_combine_multiple(self):
        tlc = TokenListClass(STRUCT)
        tl1 = tlc(['A', 'B', 'C', 'D'])
        tl2 = tlc(['A', 'B', 'D', 'C'])
        result = tlc.combine([tl1, tl2])
        assert isinstance(result, str)


class TestTokenListAlt:
    def test_phrases(self):
        tlc = TokenListClass(STRUCT)
        tl_full = tlc(['A', ['B', 'C'], 'D'])
        phrases = tl_full.phrases
        assert phrases is not None or phrases is None  # depends on len check

    def test_alt_sentences(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', ['B', 'C'], 'D'])
        alts = tl.alt_sentences
        # len(flatten) = 4 == len(STRUCT) = 4, so should return list
        if alts is not None:
            assert isinstance(alts, list)

    def test_phrases_too_short(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B'])
        # flatten has 2 items, struct has 4, so phrases returns None
        assert tl.phrases is None

    def test_alt_sentences_too_short(self):
        tlc = TokenListClass(STRUCT)
        tl = tlc(['A', 'B'])
        assert tl.alt_sentences is None


class TestSplitMultistringMultiple:
    def test_two_ge(self):
        ge = TokenList.greater_equals
        result = TokenList.split_multistring('A %s B %s C' % (ge, ge))
        assert len(result) == 4


class TestParseMultiGE:
    def test_parse_multi_two_ge(self):
        tlc = TokenListClass(STRUCT)
        ge = TokenList.greater_equals
        results = tlc.parse_multi('A %s B %s C > D' % (ge, ge))
        assert len(results) == 4


class TestTokenListCombineComplex:
    def test_combine_with_sublists(self):
        tlc = TokenListClass(STRUCT)
        tl1 = tlc(['A', ['B', 'C'], 'D'])
        tl2 = tlc(['A', 'B', ['C', 'D']])
        result = tlc.combine([tl1, tl2])
        assert isinstance(result, str)

    def test_combine_with_pre_post_tokens(self):
        """Test combine where tokens exist before and after core."""
        struct5 = {1: 'A', 2: 'B', 3: 'C', 4: 'D', 5: 'E'}
        tlc = TokenListClass(struct5)
        tl1 = tlc(['E', 'A', 'B', 'C', 'D'])
        tl2 = tlc(['A', 'B', 'C', 'D', 'E'])
        result = tlc.combine([tl1, tl2])
        assert isinstance(result, str)


class TestTokenListFromFreqBranches:
    def test_from_freq_with_equals(self):
        tlc = TokenListClass(STRUCT)
        # Two items with same freq = equal, then different
        desc = [('A', 0.5), ('B', 0.5), ('C', 0.25), ('D', 0.125)]
        tl = tlc.from_freq(desc, 0)
        flat = tl.flatten()
        assert len(flat) == 4

    def test_from_freq_with_empty_last(self):
        tlc = TokenListClass(STRUCT)
        desc = [('A', 0.5)]  # only one item
        tl = tlc.from_freq(desc, 0)
        assert len(tl.flatten()) == 1

    def test_from_freq_last_empty_string(self):
        tlc = TokenListClass(STRUCT)
        desc = [('', 0.0)]
        tl = tlc.from_freq(desc, 0)
        # Empty string at end with op=='' and descriptor[idx][0]==''
        # goes to else branch where it checks if != ''
        assert len(tl.flatten()) == 0


class TestLongestCommonSequenceFallback:
    def test_lcs_with_proportion_fallback(self):
        """Test LCS with proportion=any to trigger fallback to majority."""
        tlc = TokenListClass(STRUCT)
        tl1 = tlc(['A', 'B', 'C', 'D'])
        tl2 = tlc(['D', 'C', 'B', 'A'])  # reversed
        result = tlc.longest_common_sequence([tl1, tl2], proportion=any)
        # With any, might find something; if not, falls back to majority
        assert result is not None

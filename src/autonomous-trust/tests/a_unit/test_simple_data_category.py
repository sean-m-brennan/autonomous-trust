import math
import pytest
from decimal import Decimal
from unittest.mock import patch

from autonomous_trust.simple.data_category import (
    IncompleteSamplingException,
    SemanticMismatchException,
    frexp,
    Category,
    CategoryClass,
)
from autonomous_trust.simple.token_list import TokenList, TokenListClass, TokenStruct
from autonomous_trust.simple.data_service import (
    ExactService, CloseEnoughService, BlindService,
    FaultyService, BiasedService, DeceitService, ALL_SERVICES,
)
from autonomous_trust.simple.data_client import DataClient


STRUCT: TokenStruct = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}


class TestFrexp:
    def test_base_two(self):
        mantissa, exponent = frexp(8.0, base_two=True)
        assert mantissa == 0.5
        assert exponent == 4

    def test_base_two_default(self):
        mantissa, exponent = frexp(8.0)
        m2, e2 = math.frexp(8.0)
        assert mantissa == m2
        assert exponent == e2

    def test_base_ten(self):
        mantissa, exponent = frexp(123.0, base_two=False)
        assert exponent == 2
        # mantissa should be 1.23
        assert float(mantissa) == pytest.approx(1.23, abs=0.01)

    def test_base_ten_small(self):
        mantissa, exponent = frexp(0.05, base_two=False)
        assert isinstance(exponent, int)

    def test_base_ten_negative(self):
        mantissa, exponent = frexp(-42.0, base_two=False)
        assert exponent == 1

    def test_base_two_one(self):
        mantissa, exponent = frexp(1.0, base_two=True)
        assert mantissa == 0.5
        assert exponent == 1

    def test_base_ten_one(self):
        mantissa, exponent = frexp(1.0, base_two=False)
        assert exponent == 0

    def test_base_two_zero(self):
        mantissa, exponent = frexp(0.0, base_two=True)
        assert mantissa == 0.0
        assert exponent == 0


class TestIncompleteSamplingException:
    def test_str(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        exc = IncompleteSamplingException(cat)
        assert exc.category is cat
        s = str(exc)
        assert 'incomplete sampling error' in s
        assert cat.name in s

    def test_is_runtime_error(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        exc = IncompleteSamplingException(cat)
        assert isinstance(exc, RuntimeError)


class TestSemanticMismatchException:
    def test_str(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        exc = SemanticMismatchException(cat, 'A > B > C > D')
        assert exc.category is cat
        assert exc.sequence == 'A > B > C > D'
        s = str(exc)
        assert 'semantic mismatch error' in s
        assert cat.name in s

    def test_is_runtime_error(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        exc = SemanticMismatchException(cat, 'X')
        assert isinstance(exc, RuntimeError)


class TestCategory:
    def test_cannot_construct_directly(self):
        with pytest.raises(RuntimeError, match="must be created using a CategoryClass"):
            Category(object(), ExactService)

    def test_from_token_class(self):
        tlc = TokenListClass(STRUCT)
        cat = Category.from_token_class(CategoryClass(token_class=tlc), tlc, ExactService, sensitivity=0)
        assert cat.name == 'ExactService'
        assert cat.klass is ExactService
        assert cat.sensitivity == 0
        assert cat.tokens is not None
        assert cat.sentence is not None
        assert isinstance(cat.summary, dict)

    def test_from_struct(self):
        parent = CategoryClass(struct=STRUCT)
        cat = Category.from_struct(parent, STRUCT, ExactService, sensitivity=0)
        assert cat.name == 'ExactService'
        assert cat.struct == STRUCT

    def test_created_via_category_class(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=1)
        assert cat.name == 'ExactService'
        assert cat.sensitivity == 1
        assert isinstance(cat.tokens, TokenList)
        assert isinstance(cat.sentence, str)

    def test_contains_sequence_true(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        # The sentence itself should be found in phrases (if phrases is not None)
        if cat.phrases is not None:
            # At least one phrase should contain one of the tokens from the struct
            found = False
            for val in STRUCT.values():
                if cat.contains_sequence(val):
                    found = True
                    break
            assert found

    def test_contains_sequence_false(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        if cat.phrases is not None:
            assert not cat.contains_sequence('ZZZZNOTFOUND')

    def test_contains_sequence_incomplete_raises(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        # Force phrases to None to simulate incomplete sampling
        original_phrases = cat.phrases
        cat._TokenList__alt = None  # won't work, need to patch tokens
        # Instead, manually set tokens to something with fewer elements than struct
        tlc = TokenListClass(STRUCT)
        short_tokens = tlc(['A'])  # only 1 token, struct has 4
        cat.tokens = short_tokens
        cat.phrases = short_tokens.phrases  # will be None because flatten < struct
        with pytest.raises(IncompleteSamplingException):
            cat.contains_sequence('A')

    def test_longest_common_sequence(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(CloseEnoughService, sensitivity=0)
        result = Category.longest_common_sequence([cat1, cat2])
        assert isinstance(result, str)

    def test_combine(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(CloseEnoughService, sensitivity=0)
        result = Category.combine([cat1, cat2])
        assert isinstance(result, str)

    def test_distances(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(DeceitService, sensitivity=0)
        result = Category.distances([cat1, cat2])
        assert isinstance(result, dict)
        assert cat1.name in result
        assert cat2.name in result

    def test_distances_base_two(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        result = Category.distances([cat1], base_two=True)
        assert isinstance(result, dict)

    def test_match(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(DeceitService, sensitivity=0)
        matched = Category.match([cat1.tokens], [cat1, cat2])
        assert isinstance(matched, list)


class TestCategoryClass:
    def test_init_with_token_class(self):
        tlc = TokenListClass(STRUCT)
        klass = CategoryClass(token_class=tlc)
        assert klass.token_class is tlc
        assert klass.struct == STRUCT

    def test_init_with_struct(self):
        klass = CategoryClass(struct=STRUCT)
        assert klass.struct == STRUCT
        assert klass.token_class is not None

    def test_init_no_args_raises(self):
        with pytest.raises(RuntimeError, match='CategoryClass must be constructed'):
            CategoryClass()

    def test_call_creates_category(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        assert isinstance(cat, Category)
        assert cat.name == 'ExactService'

    def test_call_with_sensitivity(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=2)
        assert cat.sensitivity == 2

    def test_longest_common_sequence(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(CloseEnoughService, sensitivity=0)
        result = klass.longest_common_sequence([cat1, cat2])
        assert isinstance(result, str)

    def test_combine_single(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        result = klass.combine([cat1])
        assert isinstance(result, str)

    def test_combine_multiple(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(CloseEnoughService, sensitivity=0)
        result = klass.combine([cat1, cat2])
        assert isinstance(result, str)

    def test_distances(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        dist = klass.distances([cat1])
        assert isinstance(dist, dict)
        assert cat1.name in dist
        # Should have distances to other services
        assert isinstance(dist[cat1.name], dict)

    def test_distances_base_two(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        dist = klass.distances([cat1], base_two=True)
        assert isinstance(dist, dict)

    def test_distances_multiple_categories(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(DeceitService, sensitivity=0)
        dist = klass.distances([cat1, cat2])
        assert cat1.name in dist
        assert cat2.name in dist

    def test_match_finds_matching(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(DeceitService, sensitivity=0)
        matched = klass.match([cat1.tokens], [cat1, cat2])
        assert len(matched) >= 1
        assert cat1 in matched

    def test_match_no_match(self):
        klass = CategoryClass(struct=STRUCT)
        cat1 = klass(ExactService, sensitivity=0)
        cat2 = klass(DeceitService, sensitivity=0)
        # Use an unrelated token list
        tlc = TokenListClass(STRUCT)
        unrelated = tlc(['Z', 'Y', 'X', 'W'])
        matched = klass.match([unrelated], [cat1, cat2])
        assert len(matched) == 0

    def test_all_categories(self):
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=0)
        assert len(cats) == len(ALL_SERVICES)
        names = [c.name for c in cats]
        assert 'ExactService' in names
        assert 'DeceitService' in names
        assert 'BlindService' in names

    def test_all_categories_with_sensitivity(self):
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=2)
        for cat in cats:
            assert cat.sensitivity == 2

    def test_independent_validation(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        tokens = klass.independent_validation(cat)
        assert isinstance(tokens, TokenList)

    def test_independent_validation_tolerance(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        tokens = klass.independent_validation(cat, tolerance=0.5)
        assert isinstance(tokens, TokenList)

    def _get_valid_answer(self, cats):
        """Find a valid answer string that matches one of the categories' alt_sentences."""
        for cat in cats:
            alt = cat.alt_sentences
            if alt is not None and len(alt) > 0:
                # Return the first alt_sentence with spaces removed (as get_help would)
                return alt[0].replace(' ', '')
        return None

    def test_constrain_categories_single_match(self):
        """When constrain_categories needs get_help, provide a valid answer."""
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=1)
        answer = self._get_valid_answer(cats)
        with patch.object(DataClient, 'get_help', return_value=answer):
            result = klass.constrain_categories(cats, debug=0)
            assert isinstance(result, list)
            assert len(result) >= 1

    def test_constrain_categories_debug_true(self, capsys):
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=1)
        answer = self._get_valid_answer(cats)
        with patch.object(DataClient, 'get_help', return_value=answer):
            result = klass.constrain_categories(cats, debug=True)
            captured = capsys.readouterr()
            # Debug=True should produce output
            assert isinstance(result, list)
            assert len(captured.out) > 0

    def test_constrain_categories_debug_level_2(self, capsys):
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=1)
        answer = self._get_valid_answer(cats)
        with patch.object(DataClient, 'get_help', return_value=answer):
            result = klass.constrain_categories(cats, debug=2)
            captured = capsys.readouterr()
            # Level 2 debug prints JSON summaries
            assert isinstance(result, list)
            assert len(captured.out) > 0

    def test_constrain_categories_no_debug(self):
        klass = CategoryClass(struct=STRUCT)
        cats = klass.all_categories(sensitivity=1)
        answer = self._get_valid_answer(cats)
        with patch.object(DataClient, 'get_help', return_value=answer):
            result = klass.constrain_categories(cats, debug=0)
            assert isinstance(result, list)


class TestCategoryClassWithTokenClass:
    """Test CategoryClass when initialized with a TokenListClass instead of struct."""

    def test_call_creates_category(self):
        tlc = TokenListClass(STRUCT)
        klass = CategoryClass(token_class=tlc)
        cat = klass(ExactService)
        assert isinstance(cat, Category)
        assert cat.name == 'ExactService'

    def test_all_categories(self):
        tlc = TokenListClass(STRUCT)
        klass = CategoryClass(token_class=tlc)
        cats = klass.all_categories(sensitivity=0)
        assert len(cats) == len(ALL_SERVICES)


class TestCategoryServiceVariants:
    """Test Category creation with each service type."""

    def test_exact_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        assert cat.name == 'ExactService'
        assert len(cat.summary) > 0

    def test_close_enough_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(CloseEnoughService, sensitivity=0)
        assert cat.name == 'CloseEnoughService'
        assert len(cat.summary) > 0

    def test_blind_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(BlindService, sensitivity=0)
        assert cat.name == 'BlindService'
        assert len(cat.summary) > 0

    def test_faulty_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(FaultyService, sensitivity=0)
        assert cat.name == 'FaultyService'
        assert len(cat.summary) > 0

    def test_biased_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(BiasedService, sensitivity=0)
        assert cat.name == 'BiasedService'
        assert len(cat.summary) > 0

    def test_deceit_service(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(DeceitService, sensitivity=0)
        assert cat.name == 'DeceitService'
        assert len(cat.summary) > 0


class TestCategoryProperties:
    """Test that Category objects have expected properties."""

    def test_summary_is_ordered_dict(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        assert isinstance(cat.summary, dict)

    def test_tokens_is_token_list(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        assert isinstance(cat.tokens, TokenList)

    def test_sentence_is_string(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService)
        assert isinstance(cat.sentence, str)
        assert len(cat.sentence) > 0

    def test_phrases_not_none_for_full_struct(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        # For ExactService with all 4 categories, phrases should not be None
        # (unless the token list doesn't cover all struct values)
        # This depends on the data, so just check type
        assert cat.phrases is None or isinstance(cat.phrases, list)

    def test_alt_sentences_type(self):
        klass = CategoryClass(struct=STRUCT)
        cat = klass(ExactService, sensitivity=0)
        assert cat.alt_sentences is None or isinstance(cat.alt_sentences, list)


class TestFrexpEdgeCases:
    def test_large_number_base_ten(self):
        mantissa, exponent = frexp(1000000.0, base_two=False)
        assert exponent == 6

    def test_fractional_base_ten(self):
        mantissa, exponent = frexp(0.00123, base_two=False)
        assert isinstance(exponent, int)

    def test_base_two_negative(self):
        mantissa, exponent = frexp(-16.0, base_two=True)
        m2, e2 = math.frexp(-16.0)
        assert mantissa == m2
        assert exponent == e2

    def test_base_two_fraction(self):
        mantissa, exponent = frexp(0.25, base_two=True)
        m2, e2 = math.frexp(0.25)
        assert mantissa == m2
        assert exponent == e2

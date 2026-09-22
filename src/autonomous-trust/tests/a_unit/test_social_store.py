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

"""The durable block store, and the exact bytes both runtimes write.

Twin of C ``test/social_store_test.c`` (Phase 4 P4.1). The golden string below
is the same one that file pins, character for character.

WHY A GOLDEN STRING RATHER THAN A ROUND TRIP ALONE. A round trip proves only
that the file can be re-read by the thing that wrote it, which is the weakest
useful claim: two runtimes can each round-trip their own incompatible format
forever. The document is a CROSS-LANGUAGE contract, so both sides pin the
bytes. If either serializer drifts -- indentation, key order, number
formatting, a field appearing only when it happens to be set -- exactly one of
the two tests fails, and it names which side moved.

WHY NOT A CONFORMANCE CASE. A live block stamps the wall clock, so two runtimes
blocking the same peer legitimately write different ``at`` values; comparing
live files would be comparing clocks. What must agree is the SERIALIZATION of a
given block set.
"""

import json
import os

import pytest

from autonomous_trust.core._python.identity.social_store import (
    SOCIAL_FILENAME, SOCIAL_STORE_VERSION,
    social_store_load, social_store_save)

# Deliberately NOT in sorted order: the writer must sort them, and seeding them
# already-sorted would let an unsorted writer pass. The timestamps differ in
# shape too -- one integral, one fractional -- because number formatting is
# exactly the kind of thing that drifts silently between a C and a Python
# serializer.
UUID_A = '0a000000-0000-4000-8000-00000000000a'
UUID_B = '0c000000-0000-4000-8000-00000000000b'
AT_A = 1750000001.5
AT_B = 1750000000.0

GOLDEN = (
    '{\n'
    '  "blocks": {\n'
    '    "' + UUID_A + '": {\n'
    '      "at": 1750000001.5,\n'
    '      "reason": ""\n'
    '    },\n'
    '    "' + UUID_B + '": {\n'
    '      "at": 1750000000.0,\n'
    '      "reason": ""\n'
    '    }\n'
    '  },\n'
    '  "version": 1\n'
    '}'
)


def _seed():
    # B first, so a writer that preserved insertion order would emit them in
    # the wrong order and fail the golden comparison.
    return {UUID_B: AT_B, UUID_A: AT_A}


def test_the_bytes_are_what_c_writes(tmp_path):
    social_store_save(_seed(), str(tmp_path))
    raw = (tmp_path / SOCIAL_FILENAME).read_bytes()
    assert raw.decode('utf-8') == GOLDEN


def test_a_saved_set_loads_back_unchanged(tmp_path):
    social_store_save(_seed(), str(tmp_path))
    back = social_store_load(str(tmp_path))
    assert set(back) == {UUID_A, UUID_B}
    assert back[UUID_A] == pytest.approx(AT_A)
    assert back[UUID_B] == pytest.approx(AT_B)


def test_no_file_is_an_empty_store_not_an_error(tmp_path):
    """The ordinary first boot. Raising here would make every fresh node
    report a failure it cannot act on."""
    assert social_store_load(str(tmp_path)) == {}


def test_a_corrupt_file_is_refused_rather_than_partly_believed(tmp_path):
    """Fails toward "nobody is blocked", never toward an arbitrary subset.

    A partial restore is the worst outcome: the operator would see some of
    their blocks working and reasonably assume the rest were too. C returns -1
    and empties the store; Python raises and the caller empties it, which
    ``IdentityProcess.load_social_blocks`` does.
    """
    (tmp_path / SOCIAL_FILENAME).write_text(
        '{"version": 1, "blocks": "not an object"}')
    with pytest.raises(ValueError):
        social_store_load(str(tmp_path))


def test_an_unblock_is_a_delete_so_the_file_shrinks(tmp_path):
    social_store_save(_seed(), str(tmp_path))
    blocks = _seed()
    del blocks[UUID_A]
    social_store_save(blocks, str(tmp_path))
    back = social_store_load(str(tmp_path))
    # Gone, not flagged: "blocked" IS membership, so nothing can disagree with
    # it and re-blocking is idempotent.
    assert UUID_A not in back
    assert UUID_B in back


def test_the_version_is_written_but_not_enforced_on_read(tmp_path):
    """An older reader meeting a newer document keeps the blocks it
    understands rather than discarding somebody's moderation state over a
    number. Both runtimes read the field and act on neither."""
    doc = {
        'version': SOCIAL_STORE_VERSION + 99,
        'blocks': {UUID_A: {'at': AT_A, 'reason': ''}},
    }
    (tmp_path / SOCIAL_FILENAME).write_text(json.dumps(doc))
    assert set(social_store_load(str(tmp_path))) == {UUID_A}


def test_an_entry_missing_its_timestamp_still_blocks(tmp_path):
    """``at`` is bookkeeping; the KEY is the block. A document hand-edited to
    drop it must not silently unblock somebody."""
    doc = {'version': 1, 'blocks': {UUID_A: {}}}
    (tmp_path / SOCIAL_FILENAME).write_text(json.dumps(doc))
    back = social_store_load(str(tmp_path))
    assert UUID_A in back
    assert back[UUID_A] == 0.0

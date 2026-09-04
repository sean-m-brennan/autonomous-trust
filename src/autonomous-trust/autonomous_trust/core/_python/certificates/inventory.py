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
"""Which capabilities are exactly checkable, and which are not.

doc/verification_oracle.md asks that "a capability whose result cannot be
certified should be recognized as the expensive case rather than treated as the
normal one". Recognition is not automatic --- a node that simply falls through
to completion scoring for everything it cannot check looks, from the outside,
exactly like a node that is checking everything. The inventory is what makes
the difference visible.

Four states per capability, and the ordering is by how much is known:

``certified``
    Declared with a checker, and a witness is required. Answers are verified
    exactly.
``optional``
    Declared with a checker, but a missing witness falls through rather than
    counting against the peer. The migration state.
``uncertifiable``
    Declared with ``checker: null``. Somebody looked and concluded no witness
    exists. This is the expensive case, acknowledged.
``unexamined``
    Registered on this node but absent from the declaration. Nobody has
    considered it, which is a different problem from having considered it and
    concluded nothing can be done --- and it is the state the inventory exists
    to surface, because it is the one that accumulates silently.

The report is emitted once when the layer initialises, at INFO, and returned as
data so a test, an operator tool or the conformance corpus can assert on it
rather than scrape a log line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .model import CertificateModel

CERTIFIED = 'certified'
OPTIONAL = 'optional'
UNCERTIFIABLE = 'uncertifiable'
UNEXAMINED = 'unexamined'

#: Report order: worst-known first, so the line an operator most needs is not
#: at the bottom of an alphabetical list.
STATE_ORDER = (UNEXAMINED, UNCERTIFIABLE, OPTIONAL, CERTIFIED)


@dataclass(frozen=True)
class InventoryRow:
    capability: str
    state: str
    checker: Optional[str] = None
    note: str = ''


def build_inventory(model: CertificateModel,
                    registered: Optional[Iterable[str]] = None
                    ) -> list[InventoryRow]:
    """Classify every capability this node knows about.

    ``registered`` is the node's own capability names. Declarations naming a
    capability this node does not have are still reported --- a scenario's
    declaration is written once for the whole cohort, and a row for a
    capability held only by peers is information, not an error.
    """
    names = set(registered or ())
    names.update(model.capabilities.keys())
    rows: list[InventoryRow] = []
    for name in sorted(names):
        decl = model.capabilities.get(name)
        if decl is None:
            rows.append(InventoryRow(name, UNEXAMINED))
        elif not decl.certifiable:
            rows.append(InventoryRow(name, UNCERTIFIABLE, None, decl.note))
        elif decl.required:
            rows.append(InventoryRow(name, CERTIFIED, decl.checker, decl.note))
        else:
            rows.append(InventoryRow(name, OPTIONAL, decl.checker, decl.note))
    rows.sort(key=lambda r: (STATE_ORDER.index(r.state), r.capability))
    return rows


def summarise(rows: Iterable[InventoryRow]) -> dict[str, int]:
    """Counts per state, including the states with none."""
    counts = {state: 0 for state in STATE_ORDER}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    return counts


def format_inventory(rows: Iterable[InventoryRow]) -> str:
    """A short operator-facing report.

    Self-diagnosing rather than a bare tally: the header says what the numbers
    mean, and each row carries the reason a capability is where it is, so the
    reader does not have to know the vocabulary to act on it.
    """
    rows = list(rows)
    counts = summarise(rows)
    lines = [
        'certificate inventory: %d exactly checkable, %d optional, '
        '%d acknowledged uncertifiable, %d never examined'
        % (counts[CERTIFIED], counts[OPTIONAL], counts[UNCERTIFIABLE],
           counts[UNEXAMINED]),
    ]
    for row in rows:
        detail = f' via {row.checker}' if row.checker else ''
        why = f' -- {row.note}' if row.note else ''
        if row.state == UNEXAMINED:
            why = why or ' -- not mentioned in the declaration'
        lines.append(f'  {row.state:<14} {row.capability}{detail}{why}')
    return '\n'.join(lines)

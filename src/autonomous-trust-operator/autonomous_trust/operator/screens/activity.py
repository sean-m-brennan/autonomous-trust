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
"""Activity / Results view (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.7 #4): a live
stream of submitted tasks and the ``TaskResult``s that come back, each with a
proof-verification badge and round-trip latency. Tasks are keyed by UUID so an
out-of-order result still finds its submitted row. The view only reads DTO-shaped
objects (``.uuid``, ``.result``, ``.verify_proof()``) -- it never imports AT
internals."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static


def _proof_badge(verdict: Optional[bool]) -> str:
    """Render a TaskResult.verify_proof() result (True/False/None)."""
    if verdict is True:
        return '[green]✓ verified[/]'
    if verdict is False:
        return '[red]✗ invalid[/]'
    return '[dim]— none[/]'


class ActivityView(Vertical):
    """Submitted-task / result ledger. Drive with :meth:`record_submitted` when a
    task goes out and :meth:`record_result` when a ``TaskResult`` comes back."""

    COLUMNS = ('Task', 'Capability', 'Status', 'Proof', 'Latency')

    def __init__(self, clock=time.monotonic, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._clock = clock
        # uuid(str) -> {'submitted': float, 'result': Any}
        self._tasks: Dict[str, Dict[str, Any]] = {}

    def compose(self) -> ComposeResult:
        yield DataTable(id='activity-table', zebra_stripes=True, cursor_type='row')
        yield Static('[dim]No requests yet — submit one from the Request tab.[/]',
                     id='activity-detail')

    def on_mount(self) -> None:
        table = self.query_one('#activity-table', DataTable)
        for col in self.COLUMNS:
            table.add_column(col, key=col)

    # -- updates ----------------------------------------------------------

    def record_submitted(self, uuid: Any, capability: str) -> None:
        key = str(uuid)
        if key in self._tasks:
            return
        self._tasks[key] = {'submitted': self._clock(), 'result': None}
        try:
            table = self.query_one('#activity-table', DataTable)
        except Exception:
            return
        table.add_row(key[:8], capability or '—', '[yellow]pending[/]',
                      _proof_badge(None), '—', key=key)

    def record_result(self, result: Any) -> None:
        key = str(getattr(result, 'uuid', '') or '')
        entry = self._tasks.get(key)
        if entry is None:
            # A result for a task we never saw submitted (e.g. resumed session);
            # surface it as its own row so nothing is silently dropped.
            self.record_submitted(key or 'unknown', getattr(result, 'capability', ''))
            entry = self._tasks.get(key)
            if entry is None:
                return
        entry['result'] = result
        verdict = None
        try:
            verdict = result.verify_proof()
        except Exception:
            verdict = None
        status = self._status_text(result)
        latency = '—'
        if entry.get('submitted') is not None:
            latency = f'{self._clock() - entry["submitted"]:.2f}s'
        try:
            table = self.query_one('#activity-table', DataTable)
            table.update_cell(key, 'Status', status)
            table.update_cell(key, 'Proof', _proof_badge(verdict))
            table.update_cell(key, 'Latency', latency)
        except Exception:
            pass

    @staticmethod
    def _status_text(result: Any) -> str:
        raw = getattr(result, 'status', None)
        raw = getattr(raw, 'value', raw)
        if raw is None:
            return '[green]done[/]'
        text = str(raw)
        color = 'red' if text in ('no_peers', 'rejected', 'cancelled') else 'green'
        return f'[{color}]{text}[/]'

    # -- drill-in ---------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = event.row_key.value
        entry = self._tasks.get(str(key))
        detail = self.query_one('#activity-detail', Static)
        if entry is None or entry.get('result') is None:
            detail.update('[dim]Awaiting result…[/]')
            return
        result = entry['result']
        verdict = None
        try:
            verdict = result.verify_proof()
        except Exception:
            verdict = None
        lines = [f'[bold]task {str(key)[:8]}[/]',
                 f'proof: {_proof_badge(verdict)}',
                 f'result: {getattr(result, "result", None)!r}']
        detail.update('\n'.join(lines))

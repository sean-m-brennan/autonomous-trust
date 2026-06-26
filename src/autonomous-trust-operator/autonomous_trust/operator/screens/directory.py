# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Resource Directory view: searchable table of resources with name, kind,
#providers, required tier, and my-reach (✓ invokable / 🔒 tier-locked / ?
unknown). Tier-locked resources are shown (not hidden) -- gating is execution-
time only -- and selecting a row drills into its providers. Fed by
``ResourceDirectory`` snapshots the bridge drains off ``external_feedback``."""
from __future__ import annotations

from typing import Any, Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Input, Static


def _reach_cell(reach_value: str, required_tier: Optional[int]) -> str:
    """Render my-reach for the table (string match keeps this independent of
    importing the Reach enum into the UI)."""
    if reach_value == 'invokable':
        return '[green]✓ invokable[/]'
    if reach_value == 'locked_by_tier':
        tier = '?' if required_tier is None else str(required_tier)
        return f'[yellow]🔒 needs tier {tier}[/]'
    return '[dim]? unknown[/]'


class DirectoryView(Vertical):
    """Filterable resource table. Call :meth:`update_directory` with a
    ``ResourceDirectory`` snapshot to (re)populate."""

    COLUMNS = ('Resource', 'Kind', 'Providers', 'Req. tier', 'My reach')

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._directory: Any = None
        self._filter: str = ''
        self._selected: Optional[str] = None  # drill-down survives re-renders

    def compose(self) -> ComposeResult:
        yield Input(placeholder='filter resources…', id='dir-filter')
        yield DataTable(id='dir-table', zebra_stripes=True, cursor_type='row')
        yield Static('', id='dir-detail')

    def on_mount(self) -> None:
        table = self.query_one('#dir-table', DataTable)
        for col in self.COLUMNS:
            table.add_column(col, key=col)
        self._render_rows()

    # -- data -------------------------------------------------------------

    def update_directory(self, directory: Any) -> None:
        self._directory = directory
        self._render_rows()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == 'dir-filter':
            self._filter = event.value.strip().lower()
            self._render_rows()

    def _resources(self) -> list:
        if self._directory is None:
            return []
        resources = list(getattr(self._directory, 'resources', []))
        if self._filter:
            f = self._filter
            resources = [r for r in resources
                         if f in r.name.lower()
                         or f in (r.kind or '').lower()
                         or f in (r.description or '').lower()]
        return sorted(resources, key=lambda r: r.name)

    def _render_rows(self) -> None:
        try:
            table = self.query_one('#dir-table', DataTable)
        except Exception:
            return  # not mounted yet
        table.clear()
        resources = self._resources()
        if not resources:
            self.query_one('#dir-detail', Static).update(
                '[dim]No resources yet — waiting for a directory snapshot.[/]'
                if self._directory is None else
                '[dim]No resources match the filter.[/]')
            return
        for res in resources:
            req = '—' if res.required_tier is None else str(res.required_tier)
            table.add_row(
                res.name,
                res.kind or 'unknown',
                str(len(res.providers)),
                req,
                _reach_cell(getattr(res.my_reach, 'value', res.my_reach), res.required_tier),
                key=res.name)
        # Preserve the operator's drill-down across re-renders: a periodic
        # directory snapshot re-renders rows, so re-show the selected resource's
        # detail if it's still listed rather than clobbering it with the summary.
        selected = next((r for r in resources if r.name == self._selected), None)
        if selected is not None:
            self._show_detail(selected)
        else:
            self._selected = None
            my_tier = getattr(self._directory, 'my_tier', 0)
            self.query_one('#dir-detail', Static).update(
                f'[dim]{len(resources)} resource(s) · your tier: {my_tier} · '
                f'select a row for providers[/]')

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        name = event.row_key.value
        res = next((r for r in self._resources() if r.name == name), None)
        if res is None:
            return
        self._selected = name
        self._show_detail(res)

    def _show_detail(self, res: Any) -> None:
        lines = [f'[bold]{res.name}[/]  ({res.kind or "unknown"})']
        if res.description:
            lines.append(res.description)
        req = 'unknown' if res.required_tier is None else str(res.required_tier)
        lines.append(f'required tier: {req}   reach: '
                     f'{getattr(res.my_reach, "value", res.my_reach)}')
        if res.arg_schema:
            args = ', '.join(f'{k}:{v}' for k, v in res.arg_schema.items())
            lines.append(f'args: {args}')
        if res.providers:
            lines.append('[bold]providers:[/]')
            for p in res.providers:
                rep = '—' if p.reputation is None else f'{p.reputation:.2f}'
                dot = '[green]●[/]' if p.online else '[red]○[/]'
                lines.append(f'  {dot} {p.name or p.peer}  tier {p.tier}  rep {rep}')
        else:
            lines.append('[dim]no providers[/]')
        self.query_one('#dir-detail', Static).update('\n'.join(lines))

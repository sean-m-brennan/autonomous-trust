# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the dashboard static PNG-export helper."""

from __future__ import annotations

import plotly.graph_objects as go
import pytest

from autonomous_trust.inspector.dashboard.figure_export import (
    FigureExportError, figure_to_png, png_export_available,
)

_HAVE_KALEIDO = png_export_available()


def test_png_export_available_is_bool():
    assert isinstance(png_export_available(), bool)


def test_missing_engine_raises_actionable(monkeypatch):
    # Force the "engine missing" path regardless of what's installed by
    # making write_image raise the Plotly kaleido ValueError.
    def _boom(*_a, **_k):
        raise ValueError("Image export using the kaleido engine requires "
                         "the kaleido package")
    fig = go.Figure()
    monkeypatch.setattr(fig, "write_image", _boom)
    with pytest.raises(FigureExportError) as ei:
        figure_to_png(fig, "ignored.png")
    assert "kaleido" in str(ei.value).lower()


@pytest.mark.skipif(not _HAVE_KALEIDO, reason="kaleido not installed")
def test_round_trips_a_real_figure(tmp_path):
    fig = go.Figure(go.Scattermap(lat=[34.7], lon=[-86.6], mode="markers"))
    fig.update_layout(map_style="white-bg")
    out = tmp_path / "map.png"
    path = figure_to_png(fig, out, scale=2)
    assert path == str(out)
    assert out.exists() and out.stat().st_size > 0

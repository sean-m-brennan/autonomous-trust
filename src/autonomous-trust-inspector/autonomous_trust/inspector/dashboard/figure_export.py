# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Static PNG export for dashboard Plotly figures (slide-deck capture).

The dashboard panels render to HTML for the live browser view; this helper
adds the *static raster* path so map / chart figures can be dropped into slide
decks. It wraps Plotly's ``Figure.write_image``, which needs the ``kaleido``
engine installed (``pip install 'kaleido<1.0'`` — the 0.2.x line bundles its
own headless renderer and needs no external Chrome; kaleido 1.x requires a
separate Chrome install).

Usage::

    from autonomous_trust.inspector.dashboard.figure_export import figure_to_png
    figure_to_png(map_panel.figure(), "tactical_map.png", scale=2)

Any figure-bearing panel works the same way — ``AgencyMap.figure()``,
``TargetPositionMapPanel.figure()``, ``timeline.figure()``, … — since they all
return a ``plotly.graph_objects.Figure``.
"""

from __future__ import annotations

import os
from typing import Optional, Union

PathLike = Union[str, 'os.PathLike[str]']


class FigureExportError(RuntimeError):
    """Raised when a figure cannot be rendered to a static image."""


_MISSING_ENGINE_HINT = (
    "PNG export needs the 'kaleido' engine. Install the headless 0.2.x line "
    "(no external Chrome required):\n"
    "    pip install 'kaleido<1.0'\n"
    "kaleido 1.x works too but requires a separate Chrome install."
)


def figure_to_png(fig,
                  path: PathLike,
                  *,
                  width: Optional[int] = None,
                  height: Optional[int] = None,
                  scale: float = 2.0) -> str:
    """Render a Plotly figure to a PNG file and return the path.

    ``scale`` multiplies the pixel dimensions (2.0 → crisp on a projector /
    retina deck). ``width`` / ``height`` override the figure's own layout
    size. Raises :class:`FigureExportError` with an actionable message if the
    kaleido engine is missing or the render fails, rather than leaking the
    raw Plotly/ValueError so callers can surface one clear remediation.
    """
    try:
        fig.write_image(os.fspath(path), format="png",
                        width=width, height=height, scale=scale)
    except ValueError as exc:
        # Plotly raises ValueError("...requires the kaleido package...")
        # when the engine isn't importable.
        if "kaleido" in str(exc).lower():
            raise FigureExportError(_MISSING_ENGINE_HINT) from exc
        raise FigureExportError(f"PNG export failed: {exc}") from exc
    except Exception as exc:  # engine present but render blew up
        raise FigureExportError(f"PNG export failed: {exc}") from exc
    return os.fspath(path)


def png_export_available() -> bool:
    """Return True if a static-image engine (kaleido) is importable.

    Cheap pre-flight so a caller (e.g. a deck-export button) can hide or grey
    out the option instead of catching :class:`FigureExportError`.
    """
    try:
        import kaleido  # noqa: F401
    except ImportError:
        return False
    return True

# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Multi-agency demo bridge wiring.

Maps the disaster-response capability set (NOAA / USGS / EPA / FEMA
streams) to the remote peer-process queue names and hands the result
to the generic ``InspectorBridge`` in
``autonomous_trust.inspector.bridge``.

Other scenarios should import that ``spawn_bridge`` directly with
their own cap → proc map; this module is purely the multi-agency-demo
configuration of that shared machinery.
"""

from __future__ import annotations

from autonomous_trust.core import LogLevel
from autonomous_trust.inspector.bridge import (
    BRIDGE_QUEUE_MAX,
    BridgeDataRcvr,
    InspectorBridge,
    spawn_bridge as _spawn_bridge,
)


# Capability name -> remote process queue name. Each remote peer's
# data-stream worker listens on the queue named here; ``InspectorBridge``
# uses this to route DataProtocol.request messages.
MULTI_AGENCY_CAP_MAP: dict[str, str] = {
    'weather_stream':    'weather-stream',
    'seismic_stream':    'seismic-stream',
    'airquality_stream': 'airquality-stream',
    'situation_report':  'situation-report',
    'data_fusion':       'data-fusion',
}


def spawn_bridge(bridge_queue, log_level=LogLevel.WARNING):
    """Start the generic InspectorBridge wired for the multi-agency demo."""
    return _spawn_bridge(
        bridge_queue,
        MULTI_AGENCY_CAP_MAP,
        thread_name="multi-agency-bridge",
        log_level=log_level,
    )


__all__ = [
    'BRIDGE_QUEUE_MAX',
    'BridgeDataRcvr',
    'InspectorBridge',
    'MULTI_AGENCY_CAP_MAP',
    'spawn_bridge',
]

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

"""
NTP time offset tracking for distributed clock synchronization.

Queries an NTP server periodically and maintains a running offset
that system.now() applies to local system time. Falls back gracefully
to zero offset if NTP is unavailable.
"""

import logging
import threading
import time
from datetime import timedelta

logger = logging.getLogger(__name__)

# Global NTP offset applied by system.now()
_ntp_offset: timedelta = timedelta(0)
_ntp_lock = threading.Lock()


def get_offset() -> timedelta:
    """Return the current NTP offset."""
    with _ntp_lock:
        return _ntp_offset


def _update_offset(server: str = 'pool.ntp.org', timeout: float = 5.0):
    """Query an NTP server and update the global offset."""
    global _ntp_offset
    try:
        import ntplib
        client = ntplib.NTPClient()
        response = client.request(server, version=3, timeout=timeout)
        with _ntp_lock:
            _ntp_offset = timedelta(seconds=response.offset)
        logger.debug('NTP offset updated: %.3f ms', response.offset * 1000)
    except ImportError:
        logger.debug('ntplib not installed — using local system time')
    except Exception as e:
        logger.debug('NTP query failed: %s — keeping previous offset', e)


def start_sync(server: str = 'pool.ntp.org', interval: float = 300.0):
    """Start a background thread that periodically syncs NTP offset.

    Args:
        server: NTP server hostname
        interval: Seconds between NTP queries (default: 5 minutes)
    """
    def _sync_loop():
        while True:
            _update_offset(server)
            time.sleep(interval)

    thread = threading.Thread(target=_sync_loop, daemon=True, name='ntp-sync')
    thread.start()
    logger.info('NTP sync started (server=%s, interval=%ds)', server, interval)
    return thread

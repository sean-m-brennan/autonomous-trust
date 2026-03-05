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
Python wrappers for the C ``datetime_t`` and ``timedelta_t`` types.

Provides conversion to/from Python ``datetime.datetime`` and
``datetime.timedelta``.
"""

import datetime as _dt

from .._ffi import ffi, lib

MAX_DT_STR = 512


class DateTime:
    """Wrapper around C ``datetime_t`` with Python datetime conversion."""

    __slots__ = ('_cdata',)

    def __init__(self, *, _cdata=None):
        if _cdata is not None:
            self._cdata = _cdata
        else:
            self._cdata = ffi.new('datetime_t *')

    @classmethod
    def now(cls, utc=True):
        """Get the current time."""
        obj = cls()
        rc = lib.datetime_now(not utc, obj._cdata)
        if rc != 0:
            raise RuntimeError(f"datetime_now failed with rc={rc}")
        return obj

    @classmethod
    def from_iso_string(cls, s):
        """Parse an ISO 8601 string."""
        obj = cls()
        rc = lib.datetime_from_isostring(s.encode('utf-8'), obj._cdata)
        if rc != 0:
            raise ValueError(f"Failed to parse datetime: {s!r}")
        return obj

    @classmethod
    def from_python(cls, dt):
        """Create from a Python datetime.datetime."""
        import calendar
        timestamp = calendar.timegm(dt.utctimetuple()) if dt.tzinfo else \
            int(dt.timestamp())
        nsec = dt.microsecond * 1000
        is_local = dt.tzinfo is None
        obj = cls()
        rc = lib.datetime_from_time(timestamp, nsec, is_local, obj._cdata)
        if rc != 0:
            raise RuntimeError(f"datetime_from_time failed with rc={rc}")
        return obj

    def to_iso_string(self):
        """Format as ISO 8601."""
        buf = ffi.new('char[]', MAX_DT_STR)
        rc = lib.datetime_to_isoformat(self._cdata, buf, MAX_DT_STR)
        if rc != 0:
            raise RuntimeError(f"datetime_to_isoformat failed with rc={rc}")
        return ffi.string(buf).decode('utf-8')

    def to_python(self):
        """Convert to Python datetime.datetime (UTC)."""
        iso = self.to_iso_string()
        return _dt.datetime.fromisoformat(iso)

    def __repr__(self):
        try:
            return f'DateTime({self.to_iso_string()!r})'
        except Exception:
            return 'DateTime(<error>)'


class TimeDelta:
    """Wrapper around C ``timedelta_t`` with Python timedelta conversion."""

    __slots__ = ('_cdata',)

    def __init__(self, *, _cdata=None, days=0, seconds=0, nanoseconds=0):
        if _cdata is not None:
            self._cdata = _cdata
        else:
            self._cdata = ffi.new('timedelta_t *')
            self._cdata.days = days
            self._cdata.seconds = seconds
            self._cdata.nsecs = nanoseconds

    @classmethod
    def from_string(cls, s):
        """Parse from string representation."""
        obj = cls()
        rc = lib.timedelta_from_string(s.encode('utf-8'), obj._cdata)
        if rc != 0:
            raise ValueError(f"Failed to parse timedelta: {s!r}")
        return obj

    @classmethod
    def from_python(cls, td):
        """Create from Python datetime.timedelta."""
        return cls(days=td.days, seconds=td.seconds,
                   nanoseconds=td.microseconds * 1000)

    def to_string(self):
        """Format as string."""
        buf = ffi.new('char[]', MAX_DT_STR)
        rc = lib.timedelta_to_string(self._cdata, buf, MAX_DT_STR)
        if rc != 0:
            raise RuntimeError(f"timedelta_to_string failed with rc={rc}")
        return ffi.string(buf).decode('utf-8')

    def to_python(self):
        """Convert to Python datetime.timedelta."""
        return _dt.timedelta(
            days=self._cdata.days,
            seconds=self._cdata.seconds,
            microseconds=self._cdata.nsecs // 1000,
        )

    @property
    def days(self):
        return self._cdata.days

    @property
    def seconds(self):
        return self._cdata.seconds

    @property
    def nanoseconds(self):
        return self._cdata.nsecs

    def __repr__(self):
        return (f'TimeDelta(days={self._cdata.days}, '
                f'seconds={self._cdata.seconds}, '
                f'nanoseconds={self._cdata.nsecs})')

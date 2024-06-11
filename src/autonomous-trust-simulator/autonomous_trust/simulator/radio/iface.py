# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from ..serialize import SerializableEnum


class Antenna(SerializableEnum):
    DIPOLE = 'dipole'
    YAGI = 'yagi'
    PARABOLIC = 'parabolic'

    @property
    def gain(self):
        """Antenna gain in dBm"""
        if self.value == 'dipole':
            return 3.0
        if self.value == 'yagi':
            return 12.0
        if self.value == 'parabolic':
            return 25.0


class NetInterface(SerializableEnum):
    """Classes of network interfaces with transfer rate and identifier mark"""
    SMALL = 'small'
    MEDIUM = 'medium'
    LARGE = 'large'
    POINT_TO_POINT = LARGE  # eg. laser

    @property
    def rate(self):
        """Transfer rate in bps"""
        if self.value == 'small':
            return 10 * 1000  # 10Kbps
        if self.value == 'medium':
            return 10 * 1000 * 1000 # 10Mbps
        if self.value == 'large':
            return 10 * 1000 * 1000 * 1000 # 10Gbps

    @property
    def mark(self):
        """iptables mark"""
        if self.value == 'small':
            return 11
        if self.value == 'medium':
            return 22
        if self.value == 'large':
            return 33

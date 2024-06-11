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

import os

from autonomous_trust.core import Configuration
from autonomous_trust.services.video.server import VideoConfig


class SimVideoSrc(VideoConfig):
    @classmethod
    def initialize(cls, idx: int = 0, size: int = 320, speed: int = 1):
        video_map = {1: 15, 2: 17, 3: 18, 4: 20, 5: 21}
        if idx in video_map.keys():
            path = os.path.join(Configuration.get_data_dir(), 'video',
                                '220505_02_MTB_4k_0%d.mp4' % video_map[idx])
            return SimVideoSrc(path, size, speed)
        return None

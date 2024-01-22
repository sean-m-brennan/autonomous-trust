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

from queue import Full, Empty

from autonomous_trust.services.data.client import DataRcvr
from autonomous_trust.services.data.server import DataProtocol


class DataSimRcvr(DataRcvr):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies, **kwargs)

    def handle_data(self, _, message):
        if message.function == DataProtocol.data:
            try:
                uuid = message.from_whom.uuid
                hdr = message.obj[:self.hdr_size]
                data = message.obj[self.hdr_size:]
                if uuid in self.cohort.peers:
                    self.cohort.peers[uuid].video_stream.put(msg, block=True, timeout=self.q_cadence)
            except (Full, Empty):
                pass

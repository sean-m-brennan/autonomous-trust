from . import net_util as net
from .sim_data import SimState


class SimClient(net.Client):
    header_fmt = '!Q'

    def recv_data(self, **kwargs) -> SimState:
        data = self.recv_all(self.header_fmt)
        return SimState.from_yaml_string(data)

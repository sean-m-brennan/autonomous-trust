from ..config.configuration import Configuration
from ..identity.identity import Identity


class Network(Configuration):
    encoding = 'utf-8'
    broadcast = 'anyone'

    def __init__(self, _ip4_address, _ip6_address, _mac_address):
        self._ip4_address = _ip4_address
        self._ip6_address = _ip6_address
        self._mac_address = _mac_address

    @property
    def ip4(self):
        return self._ip4_address

    @property
    def ip6(self):
        return self._ip6_address

    @property
    def mac(self):
        return self._mac_address

    @staticmethod
    def initialize(my_ip4, my_ip6, my_mac):
        return Network(my_ip4, my_ip6, my_mac)


class Message(object):
    """
    Wraps message data for IPC use, not for line transmission
    """
    def __init__(self, msg_type, obj, to_whom=None, from_whom=None):
        self.msg_type = msg_type
        self.obj = obj
        self.to_whom = to_whom
        if to_whom != Network.broadcast:
            if to_whom is None:
                self.to_whom = []
            elif isinstance(to_whom, Identity):
                self.to_whom = [to_whom]
            elif hasattr(to_whom, '__iter__'):
                if not isinstance(to_whom[0], Identity):
                    raise RuntimeError('Invalid to_whom arg. Must be a list of Identity, but got %s' % type(to_whom[0]))
            else:
                raise RuntimeError('Invalid to_whom arg. Must be an Identity, but got %s' % type(to_whom))
        self.from_whom = from_whom
        if isinstance(obj, str) and obj.startswith(Configuration.YAML_PREFIX):
            self.obj = Configuration.from_yaml_string(obj)

    def __str__(self):
        obj_str = str(self.obj)
        if isinstance(self.obj, Configuration):
            obj_str = self.obj.to_yaml_string()
        '|'.join([self.msg_type.value, obj_str])

    def __bytes__(self):
        str(self).encode(Network.encoding)

    @staticmethod
    def parse(raw_msg, sender):
        if not isinstance(sender, Identity):
            raise RuntimeError('Sender must be an Identity')
        if isinstance(raw_msg, bytes):
            raw_msg = raw_msg.decode(Network.encoding)
        return Message(*raw_msg.split('|'), from_whom=sender)

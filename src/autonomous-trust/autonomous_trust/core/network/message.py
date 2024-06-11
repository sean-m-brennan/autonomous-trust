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

from ..config import Configuration
from ..identity import Identity, Group
from .network import Network


class Message(object):
    """
    Wraps message data for IPC use, not for line transmission

    Line protocol:
    ====================================
    | size | process | function | data |
    ====================================
    """
    def __init__(self, process, function, obj, to_whom=None, from_whom=None, encrypt=True, return_to=None):
        try:
            self.process = process.value
        except AttributeError:
            self.process = process
        self.encrypt = encrypt
        self.function = function
        self.obj = obj
        self.to_whom = to_whom
        if to_whom != Network.broadcast:
            if to_whom is None:
                self.to_whom = []
            elif isinstance(to_whom, Identity):
                self.to_whom = [to_whom]
            elif isinstance(to_whom, Group):
                pass
            elif hasattr(to_whom, '__iter__'):
                if len(to_whom) > 0 and not isinstance(to_whom[0], Identity):
                    raise RuntimeError('Invalid to_whom arg. Must be a list of Identity, but got %s' % type(to_whom[0]))
            else:
                raise RuntimeError('Invalid to_whom arg. Must be an Identity, but got %s' % type(to_whom))
        self.from_whom = from_whom
        self.return_to = return_to
        if isinstance(obj, str) and obj.startswith(Configuration.YAML_PREFIX):  # FIXME
            self.obj = Configuration.from_string(obj)
        # FIXME signing

    def __str__(self):
        obj_str = str(self.obj)
        # FIXME signing
        if isinstance(self.obj, Configuration):
            obj_str = self.obj.to_string()
        return '|'.join([self.process, self.function, obj_str])

    def __bytes__(self):
        return str(self).encode(Network.encoding)

    @staticmethod
    def parse(raw_msg, sender, validate=True):
        if validate and sender is not None and not isinstance(sender, Identity):
            raise RuntimeError('Sender must be an Identity')
        if isinstance(raw_msg, bytes):
            raw_msg = raw_msg.decode(Network.encoding)
        return Message(*raw_msg.split('|', 2), from_whom=sender)

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

import json
import logging
from base64 import b64encode, b64decode

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

from ..config import Configuration
from .network import Network

logger = logging.getLogger(__name__)


class Message(object):
    """
    Wraps message data for IPC use, not for line transmission

    Line protocol:
    =================================================
    | size | process | function | data | signature  |
    =================================================
    """
    def __init__(self, process, function, obj, to_whom=None, from_whom=None, encrypt=True, return_to=None):
        # Deferred import to break circular dependency:
        # network.__init__ -> message -> identity -> idprocess -> network
        from ..identity import Identity, Group

        self.verified = False
        self.signature = None
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
        if isinstance(obj, str):
            check = obj.lstrip()
            # Only auto-deserialize JSON objects that are Configuration instances
            # (have "__type__" key). Leave arrays and plain data as strings for
            # handlers to deserialize explicitly via from_json_string().
            if check.startswith('{') and '"__type__"' in obj:
                try:
                    self.obj = Configuration.from_string(obj)
                except Exception:
                    pass  # leave obj as string if deserialization fails

        # Sign message content if sender has a private signing key
        if from_whom is not None and isinstance(from_whom, Identity):
            try:
                signed = from_whom.sign(self._content_str())
                self.signature = signed.signature  # raw signature bytes
                self.verified = True  # we just signed it ourselves
            except (RuntimeError, AttributeError):
                pass  # public-only identity or mock — leave unsigned

    def _content_str(self):
        """The signable content: process|function|obj_str"""
        obj_str = str(self.obj)
        if isinstance(self.obj, Configuration):
            obj_str = self.obj.to_string()
        return '|'.join([self.process, self.function, obj_str])

    def __str__(self):
        content = self._content_str()
        if self.signature is not None:
            sig_hex = HexEncoder.encode(self.signature).decode('ascii')
            return content + '|' + sig_hex
        return content

    def __bytes__(self):
        from ..identity import Identity

        obj_str = str(self.obj)
        if isinstance(self.obj, Configuration):
            obj_str = self.obj.to_string()
        data_b64 = b64encode(obj_str.encode(Network.encoding)).decode('ascii')

        wire = {
            'process': self.process,
            'function': self.function,
            'encrypt': self.encrypt,
            'data': data_b64,
            'from_uuid': '',
            'from_name': '',
            'from_address': '',
            'from_sig_hex': '',
            'from_enc_hex': '',
        }

        if self.from_whom is not None and isinstance(self.from_whom, Identity):
            wire['from_uuid'] = str(self.from_whom.uuid)
            wire['from_name'] = getattr(self.from_whom, 'fullname', '')
            wire['from_address'] = getattr(self.from_whom, 'address', '')
            try:
                sig_pub = self.from_whom.signature.publish()
                wire['from_sig_hex'] = HexEncoder.encode(sig_pub).decode('ascii') if sig_pub else ''
            except (AttributeError, TypeError):
                pass
            try:
                enc_pub = self.from_whom.encryptor.publish()
                wire['from_enc_hex'] = HexEncoder.encode(enc_pub).decode('ascii') if enc_pub else ''
            except (AttributeError, TypeError):
                pass

        if self.signature is not None:
            wire['signature'] = HexEncoder.encode(self.signature).decode('ascii')

        return json.dumps(wire, separators=(',', ':')).encode(Network.encoding)

    @staticmethod
    def parse(raw_msg, sender, validate=True):
        from ..identity import Identity
        if validate and sender is not None and not isinstance(sender, Identity):
            raise RuntimeError('Sender must be an Identity')
        if isinstance(raw_msg, bytes):
            raw_msg = raw_msg.decode(Network.encoding)

        # Try JSON wire format first (C interop)
        try:
            wire = json.loads(raw_msg)
            if isinstance(wire, dict) and 'process' in wire and 'function' in wire:
                process = wire['process']
                function = wire['function']
                data_b64 = wire.get('data', '')
                if data_b64:
                    obj_str = b64decode(data_b64).decode(Network.encoding)
                else:
                    obj_str = ''

                msg = Message(process, function, obj_str, from_whom=sender,
                              encrypt=wire.get('encrypt', False))
                msg.verified = False

                # Verify signature if present
                sig_hex = wire.get('signature')
                if sig_hex and sender is not None and isinstance(sender, Identity):
                    try:
                        sig_bytes = HexEncoder.decode(sig_hex.encode('ascii'))
                        content = '|'.join([process, function, obj_str])
                        sender.verify(content.encode(Network.encoding), sig_bytes)
                        msg.verified = True
                    except (BadSignatureError, Exception) as e:
                        logger.warning(f"Message signature verification failed from {sender}: {e}")
                        msg.verified = False
                return msg
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

        # Fall back to pipe-separated format (legacy)
        parts = raw_msg.split('|', 3)
        if len(parts) < 3:
            raise ValueError('Malformed message: expected at least 3 fields')

        process, function, remainder = parts[0], parts[1], '|'.join(parts[2:])

        sig_hex = None
        obj_str = remainder
        if len(parts) == 4:
            obj_str = parts[2]
            sig_hex = parts[3]

        msg = Message(process, function, obj_str, from_whom=sender,
                      encrypt=False)
        msg.verified = False

        if sig_hex and sender is not None and isinstance(sender, Identity):
            try:
                sig_bytes = HexEncoder.decode(sig_hex.encode('ascii'))
                content = '|'.join([process, function, obj_str])
                sender.verify(content.encode(Network.encoding), sig_bytes)
                msg.verified = True
            except (BadSignatureError, Exception) as e:
                logger.warning(f"Message signature verification failed from {sender}: {e}")
                msg.verified = False

        return msg

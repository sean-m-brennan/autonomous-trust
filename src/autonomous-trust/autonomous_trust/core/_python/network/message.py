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
import uuid as _uuid
from base64 import b64encode, b64decode

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

from ..config import Configuration
from .network import Network
from .. import _probes

logger = logging.getLogger(__name__)


def _sig_to_hex_str(sig):
    """Render the signature stored on a Message as the 128-char wire hex.

    `Identity.sign` uses `encoder=HexEncoder`, so `Message.signature` is
    already ASCII hex (128 bytes). Older code re-applied
    `HexEncoder.encode` here, double-encoding the wire form to 256 chars
    and breaking the parse-side verification. Pass it through unchanged.
    Accepts a raw 64-byte signature too, for callers that bypass
    `Identity.sign`.
    """
    if isinstance(sig, bytes):
        if len(sig) == 64:
            return HexEncoder.encode(sig).decode('ascii')
        return sig.decode('ascii')
    if isinstance(sig, str):
        return sig
    return HexEncoder.encode(bytes(sig)).decode('ascii')


class Message(object):
    """
    Wraps message data for IPC use, not for line transmission

    Line protocol:
    =================================================
    | size | process | function | data | signature  |
    =================================================
    """
    def __init__(self, process, function, obj, to_whom=None, from_whom=None, encrypt=True, return_to=None,
                 trace_id=None):
        # Deferred import to break circular dependency:
        # network.__init__ -> message -> identity -> idprocess -> network
        from ..identity import Identity, Group

        # Always-on field (Stage 2 of debug-tooling subproject). Caller
        # may supply trace_id to preserve identity across a parse hop;
        # otherwise we mint a new one. Stored as a 32-char hex (UUID4
        # without dashes) so JSON-wire and log greps stay tidy.
        self.trace_id = trace_id or _uuid.uuid4().hex

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
                    deserialized = Configuration.from_string(obj)
                    # Only adopt when the *top-level* result is a Configuration.
                    # The "__type__" substring check above also matches
                    # NESTED Configurations inside a plain wrapper dict (e.g.
                    # partition_probe sends {'from_identity': <Identity>, ...});
                    # adopting that as self.obj turns it into a Python dict
                    # whose str() (used by _content_str and __bytes__) is the
                    # Python repr — receivers calling from_json_string()
                    # blow up with "Expecting property name enclosed in
                    # double quotes". Leaving the JSON string intact for
                    # those payloads lets the receiver round-trip cleanly.
                    if isinstance(deserialized, Configuration):
                        self.obj = deserialized
                except Exception:
                    pass  # leave obj as string if deserialization fails

        # Sign message content if sender has a private signing key.
        # NB: Identity.sign uses encoder=HexEncoder, so signed.signature is
        # the ASCII-hex form (128 bytes) — NOT raw 64-byte Ed25519 output.
        # The wire serializers and parse() account for this; do not call
        # HexEncoder.encode again on self.signature or it will double-encode.
        if from_whom is not None and isinstance(from_whom, Identity):
            try:
                signed = from_whom.sign(self._content_str())
                self.signature = signed.signature  # ASCII-hex (128 bytes)
                self.verified = True  # we just signed it ourselves
            except (RuntimeError, AttributeError):
                pass  # public-only identity or mock — leave unsigned

        # Trace event: 'new' = freshly minted; 'parse' = revived from wire.
        # Distinguish via whether the caller supplied trace_id (parse path
        # sets it, direct construction leaves None).
        _probes.emit('msg', 'new' if trace_id is None else 'parse',
                     trace_id=self.trace_id, process=self.process,
                     function=self.function, has_from=self.from_whom is not None)

    def _content_str(self):
        """The signable content: process|function|obj_str"""
        obj_str = str(self.obj)
        if isinstance(self.obj, Configuration):
            obj_str = self.obj.to_string()
        return '|'.join([self.process, self.function, obj_str])

    def __str__(self):
        content = self._content_str()
        if self.signature is not None:
            return content + '|' + _sig_to_hex_str(self.signature)
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
            'trace_id': self.trace_id,
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
            wire['signature'] = _sig_to_hex_str(self.signature)

        return json.dumps(wire, separators=(',', ':')).encode(Network.encoding)

    @staticmethod
    def parse(raw_msg, sender, validate=True):
        from ..identity import Identity
        if validate and sender is not None and not isinstance(sender, Identity):
            raise RuntimeError('Sender must be an Identity')
        # Envelope-level size cap (parser-side defense-in-depth). The TCP
        # transport already caps inbound bytes at NET_MSG_MAX_DATA, but
        # parse() is also called on in-process / alternate-transport
        # bytes; mirroring the cap here means oversized envelopes never
        # reach json.loads regardless of how they arrived. Matches C's
        # net_message_from_wire size check (net_message.c). Measured in
        # bytes — for str inputs we use len(str) which equals byte
        # length for ASCII/UTF-8 envelopes (the only wire shape AT
        # produces). Reject reason surfaces as ValueError so the
        # conformance negative_runner classifies it as
        # payload_oversized.
        wire_len = (len(raw_msg) if isinstance(raw_msg, (bytes, bytearray))
                    else len(raw_msg.encode(Network.encoding)))
        if wire_len > Network.max_wire_bytes:
            raise ValueError(
                f'wire envelope exceeds size cap '
                f'({wire_len} > {Network.max_wire_bytes} bytes)'
            )
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

                # Preserve wire trace_id across the hop. Old peers (no
                # field) → trace_id falls back to a fresh UUID, breaking
                # the chain at that hop but not the message.
                wire_trace = wire.get('trace_id') or None
                msg = Message(process, function, obj_str, from_whom=sender,
                              encrypt=wire.get('encrypt', False),
                              trace_id=wire_trace)
                msg.verified = False

                # Verify signature if present. Bypass Identity.verify's
                # two-arg path here: it forwards encoder=HexEncoder to
                # PyNaCl, but PyNaCl only applies that encoder to the
                # message arg (not the signature), so any raw signature
                # is rejected with "must be exactly 64 bytes long". Decode
                # the wire hex once ourselves and hand the 64-byte
                # signature straight to VerifyKey.verify with no encoder.
                sig_hex = wire.get('signature')
                if sig_hex and sender is not None and isinstance(sender, Identity):
                    try:
                        sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                        content = '|'.join([process, function, obj_str])
                        sender.signature.public.verify(
                            content.encode(Network.encoding), sig_raw,
                        )
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

        # Legacy pipe format carries no trace_id; fresh UUID at this hop.
        msg = Message(process, function, obj_str, from_whom=sender,
                      encrypt=False)
        msg.verified = False

        if sig_hex and sender is not None and isinstance(sender, Identity):
            try:
                # Same direct-verify path as the JSON branch above.
                sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                content = '|'.join([process, function, obj_str])
                sender.signature.public.verify(
                    content.encode(Network.encoding), sig_raw,
                )
                msg.verified = True
            except (BadSignatureError, Exception) as e:
                logger.warning(f"Message signature verification failed from {sender}: {e}")
                msg.verified = False

        return msg

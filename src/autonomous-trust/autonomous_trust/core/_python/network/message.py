# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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


def _identity_from_wire(wire):
    """Reconstruct a public ``Identity`` from the envelope ``from_*`` wire
    fields, or return ``None`` when no sender identity is present.

    The ``from_uuid`` / ``from_name`` / ``from_address`` / ``from_sig_hex`` /
    ``from_enc_hex`` envelope fields are the single canonical, cross-runtime
    representation of a message sender's identity (C ``net_message.c`` and
    Python ``Message.__bytes__`` emit the same five keys; pinned by the
    message-envelope conformance vectors). This is how a peer whose identity
    we do NOT yet know — the ``request_access`` discovery broadcast from a
    brand-new node, including a C ``at_demo`` peer — is admitted: identity
    travels in the envelope, NOT the payload (the payload carries only
    ``[package_hash, capabilities]``). The hex fields are the hex-encoded
    public keys, exactly what ``Signature``/``Encryptor`` accept with
    ``public_only=True``. The online nickname rides the envelope ``from_name``
    slot (may be empty); the local petname is never on the wire and is left
    empty. Equality/lookup for a new peer keys on uuid + public keys, which are
    all present."""
    from ..identity import Identity, Signature, Encryptor
    from_uuid = wire.get('from_uuid') or ''
    from_sig = wire.get('from_sig_hex') or ''
    from_enc = wire.get('from_enc_hex') or ''
    if not from_uuid or not from_sig or not from_enc:
        return None
    try:
        sig = Signature(from_sig.encode('ascii'), public_only=True)
        enc = Encryptor(from_enc.encode('ascii'), public_only=True)
        # Topology rank rides the envelope "from_rank" (parity with C); a peer
        # reconstructed here carries it so _member_rank sees a live value for
        # rank-based child-gateway discovery. Absent (older peer) -> 0.
        try:
            from_rank = int(wire.get('from_rank', 0) or 0)
        except (TypeError, ValueError):
            from_rank = 0
        return Identity(from_uuid, wire.get('from_address', '') or '',
                        wire.get('from_name', '') or '', sig, enc,
                        _rank=from_rank)
    except (ValueError, TypeError, RuntimeError):
        return None


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
                signed = from_whom.sign(
                    self._signable_content(self.process, self.function,
                                           self._obj_b64()))
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

    def _obj_str(self):
        """The raw body as a string (Configuration uses its canonical form)."""
        if isinstance(self.obj, Configuration):
            return self.obj.to_string()
        return str(self.obj)

    def _obj_b64(self):
        """The body as the wire base64 string (the exact `data` field)."""
        return b64encode(self._obj_str().encode(Network.encoding)).decode('ascii')

    def _content_str(self):
        """The legacy pipe-format content: process|function|raw_body.

        This is the human/legacy serialization used by ``__str__`` and the
        pipe-format ``parse`` fallback. It is NOT the signature pre-image — see
        ``_signable_content`` (which signs over the *base64* body to match the
        C / _native runtimes)."""
        return '|'.join([self.process, self.function, self._obj_str()])

    @staticmethod
    def _signable_content(process, function, data_b64):
        """Canonical signature pre-image shared with the C / _native runtimes:
        ``<process>|<function>|<base64(data)>`` (net_message.c). Signing over
        the *base64* body (not the raw body) is what lets a C ``at_demo`` peer's
        signature verify here; the two coincide only for an empty payload
        (base64('') == ''), so the old raw-body form silently passed
        request_access but rejected every non-empty C-signed message as
        "forged or corrupt"."""
        return '|'.join([process, function, data_b64])

    def __str__(self):
        content = self._content_str()
        if self.signature is not None:
            return content + '|' + _sig_to_hex_str(self.signature)
        return content

    def __bytes__(self):
        from ..identity import Identity

        data_b64 = self._obj_b64()

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
            # Sender topology rank on the envelope (mirrors C net_message.c's
            # "from_rank"). Kept in lockstep with C so the wire form stays
            # symmetric; a receiver reads it back onto the peer for rank-based
            # child-gateway discovery. 0 when no sender / unknown.
            'from_rank': 0,
        }

        if self.from_whom is not None and isinstance(self.from_whom, Identity):
            wire['from_uuid'] = str(self.from_whom.uuid)
            wire['from_name'] = getattr(self.from_whom, 'nickname', '')
            wire['from_address'] = getattr(self.from_whom, 'address', '')
            wire['from_rank'] = int(getattr(self.from_whom, '_rank', 0) or 0)
            # publish() already returns the HEX-encoded public key (bytes), e.g.
            # b'45cf..' (64 ASCII hex chars). Just decode to str — do NOT hex
            # encode it again: a second HexEncoder.encode() yields 128 chars,
            # which C's public_{encryptor,signature}_init reject (they require
            # exactly 64) and which Message.reconstruct_sender's own
            # PublicKey/VerifyKey(..., HexEncoder) parse also fails. Both the
            # parser and C expect the bare 64-char hex pubkey.
            try:
                sig_pub = self.from_whom.signature.publish()
                wire['from_sig_hex'] = sig_pub.decode('ascii') if sig_pub else ''
            except (AttributeError, TypeError):
                pass
            try:
                enc_pub = self.from_whom.encryptor.publish()
                wire['from_enc_hex'] = enc_pub.decode('ascii') if enc_pub else ''
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
                # Resolve the sender. When the network layer couldn't map
                # the source address to a known peer (sender is None) — the
                # request_access discovery broadcast from a brand-new node,
                # C or Python — reconstruct the sender identity from the
                # canonical envelope from_* fields. This is what lets a C
                # at_demo peer (which puts its identity ONLY in from_*, not
                # the payload) be admitted, and is the receive-side half of
                # the DRY request_access contract (identity in from_*,
                # payload = [package_hash, capabilities]).
                # On the broadcast/multicast channel the network layer passes
                # the source ADDRESS string as `sender` (netprocess.py:759,
                # validate=False), and on an unmatched p2p address it passes
                # None — in both cases the peer identity is not yet known. When
                # the envelope carries from_* (every request_access does, C and
                # Python alike), reconstruct the real sender Identity from it so
                # handlers receive an Identity rather than a bare address/None.
                eff_sender = sender
                if not isinstance(eff_sender, Identity):
                    reconstructed = _identity_from_wire(wire)
                    if reconstructed is not None:
                        eff_sender = reconstructed
                msg = Message(process, function, obj_str, from_whom=eff_sender,
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
                if sig_hex and eff_sender is not None and isinstance(eff_sender, Identity):
                    try:
                        sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                        # Verify over the base64 body (the exact wire `data`
                        # string), matching the sender's _signable_content and
                        # the C/_native canonical. Verifying over the decoded
                        # obj_str was the bug: it rejected every non-empty
                        # C-signed message ("forged or corrupt").
                        content = Message._signable_content(
                            process, function, data_b64)
                        eff_sender.signature.public.verify(
                            content.encode(Network.encoding), sig_raw,
                        )
                        msg.verified = True
                    except (BadSignatureError, Exception) as e:
                        logger.warning('Message signature verification failed from %s: %s', eff_sender, e)
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
                # Same direct-verify path as the JSON branch above. Sign/verify
                # over the base64 body (the canonical pre-image), not the raw
                # pipe-field obj_str.
                sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                content = Message._signable_content(
                    process, function,
                    b64encode(obj_str.encode(Network.encoding)).decode('ascii'))
                sender.signature.public.verify(
                    content.encode(Network.encoding), sig_raw,
                )
                msg.verified = True
            except (BadSignatureError, Exception) as e:
                logger.warning('Message signature verification failed from %s: %s', sender, e)
                msg.verified = False

        return msg

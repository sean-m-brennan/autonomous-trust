# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""ZTA as the identity process's admission authority (FEATURE_SPLIT_PLAN
Phase 6): the admission gate, the anchors a peer proves, the gateway and join
checks, the operator-credential classification, and background
re-verification. Moved from ``IdentityProcess`` methods to functions over the
process (``proc``), the way social's handlers are; the state they keep lives
on the process under the names it always had (``proc._zta_policy_cache``,
``proc._zta_capped``, ...), set up by :func:`init_state`.

The core reaches all of it through ``IdentityHooks`` (``_at_extension.py``)
and names none of it. Mirrors the C twin, libat_zta's zta_identity.c, and
doc/architecture/zta-integration.md.
"""
import hashlib
import time

from autonomous_trust.core._python import _probes
from autonomous_trust.core.identity.peer_standing import (
    PeerStanding, STANDING_PROVED, STANDING_CAPPED, STANDING_FAILED)
from autonomous_trust.core.identity.zta_fields import ZTA_CRED_MAX
from autonomous_trust.core.system import now

from .operator_binding import verify_operator_binding
from .zta_binding import identity_is_bound
from .zta_policy import (ZtaPolicy, ZtaPolicyError, BINDING_MODE_PREFER,
                         BINDING_MODE_REQUIRE)
from .zta_verifier import ZtaStatus

#: How often the identity loop asks whether the policy's re-verification
#: interval has elapsed. The sweep itself runs on the policy's own, much longer,
#: interval; this is only the cheap wake, so a chain walk per peer does not ride
#: the 20 s caps sweep.
ZTA_REVERIFY_CHECK_SEC = 30.0


def init_state(proc) -> None:
    """The state the functions below keep on an identity or reputation process.
    Lazily built on first use; the default policy is disabled, so a node that
    did not turn ZTA on is unaffected. Plain data, so the process still pickles
    across the fork (verifiers are built in the child)."""
    proc._zta_policy_cache = None
    proc._zta_verifier_cache = None
    proc._zta_operator_verifier_cache = None   # operator-anchor verifier (D8/Q9)
    # Per-anchor verifiers for the multi-credential admission path, one per named
    # trust anchor; separate from _zta_verifier_cache because the two answer
    # different questions ("the" verifier vs. the set a credential may chain to).
    proc._zta_anchor_cache = None
    # Anchor names OUR OWN credentials verify against (the gateway check). We never
    # admit ourselves, so nothing else computes this.
    proc._own_anchor_cache = None
    proc._zta_capped = set()          # uuids admitted via DDIL fallback (rep-capped)
    # What zta_admit found on THIS call, for publish_zta_decision: (status,
    # ceiling, verified_at, reason), or None when the gate said nothing -- silence
    # and "proved" are different claims.
    proc._zta_standing_pending = None
    # The last re-verification sweep (None: never, so the first loop sweeps at
    # once, which catches a credential revoked while this node was down), and when
    # the loop last asked whether that interval had elapsed.
    proc._last_zta_reverify = None
    proc._last_zta_reverify_check = None
    proc._operator_verified = set()   # uuids whose operator credential verified


def publish_zta_standing(proc, queues, peer_uuid, status, ceiling=None,
                          verified_at=None, reason=''):
    """Hand one ZTA finding to the other processes (doc/architecture/zta-integration.md).

    Sibling of _record_child_groups: same fan-out, different cargo. The
    reputation process is the consumer that matters -- it is where a
    ceiling can actually bound a peer -- but this goes to every process for
    the same reason a Group does, so nothing has to ask.

    Failure to propagate is logged, not raised: losing a ceiling must not
    take admission down. It is logged at WARNING with the peer and the
    ceiling, because the failure is exactly the case where a peer silently
    keeps an unbounded score.
    """
    try:
        proc.update(PeerStanding(peer_uuid, status, ceiling, verified_at,
                                reason), queues)
    except Exception as err:
        proc.logger.warning(
            'Could not propagate ZTA standing for %s (%s, ceiling %s): %s', str(peer_uuid)[:8], status, ceiling, err)


def publish_zta_decision(proc, queues, new_id):
    """Publish whatever _zta_admit just found, if it found anything.

    Nothing is sent when the gate was a no-op (policy disabled, or not
    required at admission): reputation must not be told a peer is `proved`
    merely because nobody checked. Silence leaves the peer unbounded, which
    is what a deployment that has not turned ZTA on has already chosen.
    """
    pending = proc._zta_standing_pending
    proc._zta_standing_pending = None
    if pending is None:
        return
    status, ceiling, verified_at, reason = pending
    publish_zta_standing(proc, queues, new_id.uuid, status, ceiling,
                               verified_at, reason)


def own_zta_anchors(proc) -> set:
    """Anchor names OUR OWN credentials verify against. Computed locally, once.

    Not read from ``proc.identity.zta_anchors``: that field is what a *peer*
    proved to us at admission, and we never admit ourselves. This walks our own
    credentials through the same anchor verifiers instead.
    """
    if proc._own_anchor_cache is None:
        own = set()
        identity = getattr(proc, 'identity', None)
        if identity is not None:
            anchors = zta_anchor_verifiers(proc)
            for cred, _binding, _issuer in zta_credentials(proc, identity):
                matched, _is_op, _fail, _defer = zta_match_anchors(proc, cred, anchors)
                own.update(name for name, _v, _r in matched)
        proc._own_anchor_cache = own
    return proc._own_anchor_cache


def gateway_authorized(proc, peer_uuid) -> bool:
    """Whether this node may federate through ``peer_uuid``.

    The candidate must have PROVED, at admission, an anchor we also hold. That is
    the derived-authority rule: crossing an agency boundary requires a credential
    from an agency both sides recognize, and since nothing on the wire declares
    gatewayhood, deriving the permission from verified credentials is the only
    form of it a peer cannot simply assert. A candidate we never admitted has no
    proved anchors and is refused — which is the point, not a side effect.

    Inert (True) when the policy is not enforcing at admission, or when we hold no
    anchors ourselves: with nothing to compare against, refusing every candidate
    would break federation for every non-ZTA deployment rather than protecting
    anything. Also inert on an object with no ZTA machinery wired at all, matching
    how the rest of this gate stays usable on a lightweight stand-in.
    """
    try:
        policy = zta_policy(proc)
    except AttributeError:
        return True
    if not (policy.enabled and policy.require_at_admission):
        return True
    own = own_zta_anchors(proc)
    if not own:
        return True
    peers = getattr(proc, 'peers', None)
    peer = peers.find_by_uuid(peer_uuid) if peers is not None else None
    proved = set(getattr(peer, 'zta_anchors', None) or []) if peer is not None else set()
    if proved & own:
        return True
    _probes.counter('id.gateway', 'federation_refused',
                    'no_shared_anchor' if proved else 'no_proved_anchor')
    proc.logger.warning(
        'Gateway: refusing to federate through %s: proved anchors %s share none '
        'with ours %s', peer_uuid, sorted(proved) or '[]', sorted(own))
    return False


def zta_policy(proc) -> ZtaPolicy:
    """Resolve the ZTA policy once (configs['zta_policy'] or the on-disk
    zta_policy.cfg.json, else a disabled default). Cached for the process."""
    if proc._zta_policy_cache is None:
        cfg = proc.configs.get(ZtaPolicy.CONFIG_KEY) if hasattr(proc.configs, 'get') else None
        if isinstance(cfg, ZtaPolicy):
            proc._zta_policy_cache = cfg
        else:
            try:
                proc._zta_policy_cache = ZtaPolicy.load()
            except ZtaPolicyError:
                # Never the disabled default: that is ZTA silently off. The node
                # refused to start over this already (check_config); reaching it
                # here means the file changed under a running node.
                raise
            except Exception:
                proc._zta_policy_cache = ZtaPolicy.defaults()
    return proc._zta_policy_cache


def zta_verifier(proc):
    """Build the configured verifier once (cached)."""
    if proc._zta_verifier_cache is None:
        proc._zta_verifier_cache = zta_policy(proc).create_verifier()
    return proc._zta_verifier_cache


def zta_operator_verifier(proc):
    """Build the OPERATOR-anchor verifier once (cached); None when no
    operator CA bundle is configured (ethne D8/Q9). Sentinel False marks
    "already tried, none configured" so we don't rebuild every admission."""
    if proc._zta_operator_verifier_cache is None:
        proc._zta_operator_verifier_cache = \
            zta_policy(proc).create_operator_verifier() or False
    return proc._zta_operator_verifier_cache or None


def verify_operator_key(proc, new_id, cred, claimed_key):
    """Credit a peer's OPT-IN guardian identity, if it advertised one and the
    binding holds.

    Called only once the credential is known to be operator-class: a binding
    signed by a credential with no standing to name a guardian names nobody.

    Three outcomes, and the middle one is the design:
      - no claim  -> silent. The default, and it must stay costless.
      - claim + binding verifies -> the key is written onto the peer, so from
        here on a stored peer with a key is one we verified.
      - claim + binding fails -> the key stays empty and we say so.
        operator_bound is NOT demoted: it was earned independently above, and a
        stale binding after node key rotation is an honest cause of this.
        Losing a guardian edge is the failure mode; losing admission is not.

    Mirror of the C _verify_operator_key (id_proc.c).
    """
    nick = getattr(new_id, 'nickname', '?')
    binding = getattr(new_id, 'operator_key_binding', b'') or b''
    if not claimed_key and not binding:
        return                              # declined; the normal case
    if not claimed_key or not binding:
        # Half a claim is not a claim. Worth a word either way: both halves are
        # written by one code path, so one without the other means something
        # upstream is broken, not that a peer declined.
        proc.logger.warning(
            'ZTA: %s advertised half an operator-key binding (key %s, '
            'binding %s); no guardian recorded', nick,
            'present' if claimed_key else 'absent',
            'present' if binding else 'absent')
        return
    if verify_operator_binding(new_id, cred, claimed_key, binding):
        new_id.operator_pubkey = claimed_key
        proc.logger.debug('ZTA: %s guardian key bound and verified', nick)
        _probes.emit('id.welcome', 'operator_key_bound', peer_nick=str(nick))
    else:
        proc.logger.warning(
            'ZTA: %s advertised an operator key whose binding does not verify '
            'against its operator credential; no guardian recorded '
            '(operator_bound stands on its own)', nick)
        _probes.emit('id.welcome', 'operator_key_refused', peer_nick=str(nick))
        _probes.counter('id.welcome', 'operator_key_refused')


def is_operator_credential(proc, new_id, cred) -> bool:
    """True iff ``cred`` is an operator (human-attended) credential — i.e.
    it chain-verifies against the distinct operator trust anchor (D8/Q9).

    Non-forgeable: the decision comes from verifying the actual credential
    against the operator anchor, never from the peer-advertised
    operator_bound / zta_issuer. Fail-safe: no credential, an advertised
    hash that does not match the actual bytes, no operator anchor
    configured, or a non-VERIFIED operator-chain result all yield False."""
    if not cred:
        return False
    advertised = getattr(new_id, 'zta_credential_hash', b'') or b''
    if advertised and hashlib.sha256(cred).digest() != bytes(advertised):
        # The node's advertised hash disagrees with the credential it sent —
        # do not treat as operator-class (a claim/credential mismatch).
        return False
    op_verifier = zta_operator_verifier(proc)
    if op_verifier is None:
        return False
    return op_verifier.verify_credential(cred).status is ZtaStatus.VERIFIED


def zta_credential_replayed(proc, new_id, cred) -> bool:
    """True if this exact credential is already bound to a DIFFERENT network
    identity — a harvested/replayed credential (closes doc/architecture/zta-integration.md).

    The chain-only verifier accepts a chain-valid certificate regardless of
    WHO presents it, so a credential lifted from one peer's (clear-text)
    announce could be re-announced under a different uuid/signing key and
    still pass. Here we enforce a credential↔identity uniqueness invariant: a
    credential is a one-per-identity binding. "Previously seen" = present in
    this node's peer roster (or our own identity); since rosters are built
    from announces propagated across the mesh, this is the "seen by other
    nodes" check. It is first-use-wins (TOFU): the first identity to bind a
    credential keeps it, and a later, different identity presenting the same
    credential is treated as a replay/clone and refused.

    Fingerprints are recomputed from the actual credential bytes, never the
    peer-advertised ``zta_credential_hash`` (which the announcer controls).
    Defensive about missing ``peers``/``identity`` so the gate works when
    invoked on a lightweight stand-in (no roster → no prior binding).
    """
    if not cred:
        return False
    fp = hashlib.sha256(cred).digest()
    new_uuid = getattr(new_id, 'uuid', None)
    # Our own credential must not be worn by anyone else.
    own_id = getattr(proc, 'identity', None)
    if own_id is not None:
        own = getattr(own_id, 'zta_credential', b'') or b''
        if (own and getattr(own_id, 'uuid', None) != new_uuid
                and hashlib.sha256(own).digest() == fp):
            return True
    peers = getattr(proc, 'peers', None)
    roster = list(getattr(peers, 'all', []) or []) if peers is not None else []
    for peer in roster:
        if getattr(peer, 'uuid', None) == new_uuid:
            continue  # same identity re-announcing its own credential: fine
        pc = getattr(peer, 'zta_credential', b'') or b''
        if pc and hashlib.sha256(pc).digest() == fp:
            return True
    return False


def zta_anchor_verifiers(proc):
    """``[(name, verifier, is_operator)]``, one per configured trust anchor,
    built once per process.

    The single seam for substituting verifiers in the admission path -- inject
    into ``_zta_anchor_cache`` to force a particular outcome (a verifier that
    reports UNAVAILABLE, say, to exercise the DDIL fallback).
    """
    if proc._zta_anchor_cache is None:
        proc._zta_anchor_cache = zta_policy(proc).create_anchor_verifiers()
    return proc._zta_anchor_cache


def zta_credentials(proc, new_id):
    """The peer's credentials as ``[(der, binding, issuer)]``, primary first.

    A node carries ONE credential; several arise only at a network gateway
    bridging agencies, which must hold one per agency it bridges. The primary
    lives in the singular wire fields (kept so a pre-multi-credential peer
    interoperates unchanged) and the full set in the repeated one, so the
    primary normally appears twice -- deduplicated here by fingerprint over the
    actual bytes, keeping the first occurrence but preferring whichever copy
    carries a binding, since the singular fields have nowhere to put one.
    """
    out, seen = [], {}

    def _add(der, binding, issuer):
        if not der:
            return
        der, binding = bytes(der), bytes(binding or b'')
        fp = hashlib.sha256(der).digest()
        if fp in seen:
            idx = seen[fp]
            if binding and not out[idx][1]:
                out[idx] = (der, binding, out[idx][2] or issuer)
            return
        seen[fp] = len(out)
        out.append((der, binding, issuer or ''))

    try:
        _add(getattr(new_id, 'zta_credential', b'') or b'',
             getattr(new_id, 'zta_credential_binding', b'') or b'',
             getattr(new_id, 'zta_issuer', '') or '')
    except AttributeError:
        pass  # peer from an older/non-ZTA build carries no fields
    for entry in (getattr(new_id, 'zta_credentials', None) or []):
        if isinstance(entry, dict):
            _add(entry.get('der') or entry.get('credential') or b'',
                 entry.get('binding') or b'', entry.get('issuer') or '')
        else:  # a protobuf ZtaCredential (or any duck-typed stand-in)
            _add(getattr(entry, 'der', b'') or getattr(entry, 'credential', b''),
                 getattr(entry, 'binding', b''), getattr(entry, 'issuer', ''))
    return out


def zta_match_anchors(proc, cred, anchors):
    """``(matched, is_operator, last_failure)`` for one credential.

    Every anchor is tried, deliberately not stopping at the first match: a
    credential may legitimately chain to more than one (the legacy config
    synthesizes a peer and an operator anchor that are frequently the same CA),
    and both the operator classification and gateway authority depend on knowing
    the full set rather than whichever happened to be checked first.

    ``last_failure`` carries a non-VERIFIED result so the caller can report a
    representative reason -- the observable the zta-x509-reject-* scenarios pin.
    """
    matched, is_operator, last_failure, deferred = [], False, None, None
    for name, verifier, anchor_is_operator in anchors:
        result = verifier.verify_credential(cred)
        if result.status is ZtaStatus.VERIFIED:
            matched.append((name, verifier, result))
            is_operator = is_operator or anchor_is_operator
        elif result.status in (ZtaStatus.REJECTED, ZtaStatus.EXPIRED,
                               ZtaStatus.REVOKED):
            last_failure = result
        else:  # DEFERRED / UNAVAILABLE — the verifier could not answer
            deferred = result
    return matched, is_operator, (last_failure or deferred), deferred


def zta_admit(proc, new_id) -> str:
    """ZTA admission decision for a newly-announced peer.

    Mirrors zta-integration.md §11 / the C gate: returns 'admit' (proceed,
    no cap), 'admit_capped' (DDIL fallback, reputation-capped), or 'reject'
    (do not propose). A no-op ('admit') when the policy is disabled or does
    not require verification at admission.

    **Admission is any-of** (doc/architecture/zta-integration.md): at least one
    * credential must verify
    against some configured anchor AND be bound to this identity. Each verified
    credential records authority for its anchor on the peer
    (``zta_anchors``), and that -- not a proc-declared role -- is what lets a
    node act as a gateway across an agency boundary. Gateway-ness is emergent
    from group membership and nothing on the wire declares it, so a rule of the
    form "a gateway must present N credentials" would rest on a peer's own claim
    and buy nothing; deriving authority from credentials instead is enforceable
    against a peer that simply declines to claim anything.

    **Failure is graded, because forgery and ignorance are different.** A
    binding that is present and does not verify, a credential already bound to
    another identity, an oversized blob, or an affirmatively revoked credential
    all reject the identity -- each is evidence someone is lying. A credential
    that is merely expired or chains to no anchor we hold is skipped: it says
    nothing about the peer's honesty, only about our ability to evaluate it. For
    the single-credential node this collapses to the previous behavior (nothing
    usable left => reject), which is why the zta-x509-reject-* pins still hold.

    Also sets the AUTHORITATIVE operator_bound (ethne D8/Q9): the advertised
    claim is neutralized to False on entry and set True only when a credential
    verifies against an operator-flagged trust anchor. So a disabled policy, an
    unverified peer, or a lying node (advertising operator_bound with a
    non-operator credential) all end up operator_bound=False.
    """
    # Never trust the peer-advertised operator_bound: start False and earn
    # True only via operator-anchor verification below.
    proc._mark_operator_bound(new_id, False)
    proc._zta_standing_pending = None
    # Same rule for the OPT-IN guardian identity, with one wrinkle: the claimed
    # key is part of the pre-image the operator signed, so the gate needs it —
    # it moves aside and the peer's own copy is cleared. A stored peer with a
    # key is therefore one whose binding we verified, and a policy that never
    # verifies leaves every peer keyless (the fail-safe operator_bound takes).
    claimed_key = getattr(new_id, 'operator_pubkey', b'') or b''
    new_id.operator_pubkey = b''
    policy = zta_policy(proc)
    if not (policy.enabled and policy.require_at_admission):
        return 'admit'
    nick = getattr(new_id, 'nickname', '?')

    def _reject(reason, status=ZtaStatus.REJECTED, level='warning'):
        getattr(proc.logger, level)('ZTA: rejecting %s at admission: %s',
                                    nick, reason)
        _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                     zta_status=status.value, reason=reason)
        _probes.counter('id.welcome', 'zta_rejected')
        return 'reject'

    creds = zta_credentials(proc, new_id)
    if not creds:
        # A peer presenting NOTHING still has to be evaluated, not silently
        # skipped: the verifiers are what distinguish "we cannot reach the PKI"
        # (DDIL, admit capped) from "we can, and there is no credential"
        # (reject). Iterating an empty list would answer neither, so the empty
        # credential goes through the same path every other one does and the
        # verifier says which it is -- x509 reports REJECTED "no credential
        # data", the OIDC stub reports UNAVAILABLE. That is what the
        # zta-ddil-defer and zta-x509-reject-unsigned pins turn on.
        creds = [(b'', b'', '')]
    # Size guard BEFORE handing any blob to a verifier: an oversized
    # credential is almost certainly hostile/corrupt and would let a remote
    # cause an OOM / parse-time DoS. Mirrors C `ZTA_CRED_MAX` (identity.h);
    # the C twin enforces the same cap at this admission gate (id_proc.c)
    # AND at protobuf deserialization (identity.c). Keep the bound in
    # lockstep -- pinned by conformance zta-x509-reject-oversized-credential.
    for cred, _binding, _issuer in creds:
        if len(cred) > ZTA_CRED_MAX:
            return _reject('credential too large (%d > %d)'
                           % (len(cred), ZTA_CRED_MAX))
    # Credential↔identity uniqueness: a chain-valid credential harvested from
    # another peer's announce and re-presented under a different identity is a
    # replay/clone. Rejected before chain verification -- the cert may verify
    # fine; the point is that it is already bound elsewhere. This is the
    # roster-based, first-use-wins check, which the binding below supersedes for
    # any credential that carries one; it stays because it is the only defence
    # left for an unbound credential under `binding_mode: prefer`/`off`.
    for cred, _binding, _issuer in creds:
        if zta_credential_replayed(proc, new_id, cred):
            return _reject('credential bound to a different identity (replay)')
    anchors = zta_anchor_verifiers(proc)
    mode = policy.binding_mode
    san_template = getattr(policy, 'san_uri_template', '') or ''
    usable = []          # [(anchor_name, cred, is_operator, bound)]
    earned = []          # anchor names this peer proved authority for
    last_failure = None  # a representative non-VERIFIED result, for the reason
    deferred = None      # a verifier that could not answer -> DDIL
    for cred, binding, _issuer in creds:
        matched, is_operator, failure, defer = zta_match_anchors(proc, cred, anchors)
        last_failure = failure or last_failure
        deferred = defer or deferred
        if not matched:
            continue  # chains to no anchor we hold: ignorance, not forgery
        # A chain-valid certificate may nonetheless have been revoked.
        # verify_credential does NOT consult the CRL/OCSP source (it mirrors
        # C x509_verify_credential, which only walks the chain + expiry), so
        # the admission gate must explicitly check revocation before
        # admitting. Only an affirmative REVOKED blocks: UNAVAILABLE — the
        # default when no crl_path/ocsp_url is configured — keeps the peer
        # admitted, so deployments without a revocation source see no change
        # in behavior. Mirrors the C welcoming_committee revocation gate;
        # pinned by conformance zta-x509-reject-revoked-credential.
        revoked = None
        for _name, verifier, result in matched:
            rev = verifier.check_revocation(result.credential_hash)
            if rev.status is ZtaStatus.REVOKED:
                revoked = rev
                break
        if revoked is not None:
            return _reject(revoked.reason or 'credential revoked',
                           status=ZtaStatus.REVOKED)
        # The credential is genuine. Is THIS node entitled to present it?
        # claimed_key/operator_key_binding are passed explicitly because the
        # advertised operator_pubkey was moved aside above: an opted-in node's
        # operator-key binding is itself a signature by this credential's key over
        # bytes naming this node, so it already proves entitlement.
        bound = identity_is_bound(
            new_id, cred, binding, san_template,
            operator_pubkey=claimed_key,
            operator_key_binding=getattr(new_id, 'operator_key_binding', b''))
        if binding and not bound:
            # A binding was offered and does not verify. Unlike absence, that is
            # affirmative evidence of forgery -- somebody tried and failed to
            # prove entitlement -- so it condemns the whole identity rather than
            # just costing this one credential.
            return _reject('credential binding does not verify for this identity')
        if not bound and mode == BINDING_MODE_REQUIRE:
            # Unbound is a provisioning state, not a lie. The credential is
            # unusable, so it earns no authority; if nothing else survives the
            # peer is refused below, which for a single-credential node is
            # exactly the old reject.
            proc.logger.warning(
                'ZTA: %s presented an unbound credential and binding_mode is '
                '%s; credential unusable', nick, mode)
            _probes.counter('id.welcome', 'zta_unbound_refused')
            continue
        usable.append((matched[0][0], cred, is_operator, bound))
        earned.extend(name for name, _v, _r in matched)
    if usable:
        # Record which anchors this peer actually proved. Gateway function
        # across an agency boundary is gated on this, NOT on a declared role.
        try:
            new_id.zta_anchors = sorted(set(earned))
        except Exception:
            pass
        for _anchor, cred, anchor_is_operator, _bound in usable:
            # Operator-class (D8/Q9) by either route, because a deployment may
            # express the operator anchor either way: as an anchor carrying
            # `operator: true`, or as the separate operator_ca_bundle_path that
            # _is_operator_credential consults. Both derive the answer from
            # verifying the actual credential against an operator trust anchor,
            # never from the peer-advertised operator_bound/zta_issuer.
            # _is_operator_credential additionally refuses when the peer's
            # advertised hash disagrees with the bytes it sent; the anchor-flag
            # route does not need that guard, since the chain it walked is the
            # non-forgeable signal and the advertised hash adds nothing to it.
            if not (anchor_is_operator
                    or is_operator_credential(proc, new_id, cred)):
                continue
            proc._mark_operator_bound(new_id, True)
            try:
                proc._operator_verified.add(new_id.uuid)
            except Exception:
                pass
            proc.logger.debug('ZTA: %s is operator-attended (human guardian)', nick)
            verify_operator_key(proc, new_id, cred, claimed_key)
            break
        if (mode == BINDING_MODE_PREFER
                and any(not bound for _a, _c, _o, bound in usable)):
            # `prefer` only: admitted on an unbound credential, so the
            # roster-based TOFU check is all that stood between us and a
            # harvested cert -- cap it like any other deferred verification.
            # `off` deliberately does NOT cap: absence of a binding carries no
            # penalty there, which is what makes it the no-change-in-behavior
            # setting for a deployment that has not provisioned bindings yet.
            proc.logger.info('ZTA: %s admitted on an unbound credential '
                             '(binding_mode %s); reputation cap %.2f',
                             nick, mode, policy.ddil_fallback_reputation_cap)
            _probes.counter('id.welcome', 'zta_unbound_capped')
            try:
                proc._zta_capped.add(new_id.uuid)
            except Exception:
                pass
            proc._zta_standing_pending = (
                STANDING_CAPPED, policy.ddil_fallback_reputation_cap, None,
                'admitted on an unbound credential (binding_mode %s)' % mode)
            return 'admit_capped'
        # Proved: a credential verified against a configured anchor AND is
        # bound to this identity. This is the only path that anchors the
        # doc/architecture/zta-integration.md unwind -- everything a peer earns after this moment is
        # standing a later failure calls into question.
        proc._zta_standing_pending = (
            STANDING_PROVED, None, time.time(), 'verified at admission')
        return 'admit'
    # Nothing usable. A verifier that could not answer is a DDIL condition and
    # gets the fallback; an answer we did not like is a rejection.
    if deferred is not None and last_failure is deferred:
        if policy.allow_ddil_fallback:
            proc.logger.info('ZTA: verification deferred for %s (%s); admitting '
                             'with reputation cap %.2f', nick,
                             deferred.status.value,
                             policy.ddil_fallback_reputation_cap)
            _probes.emit('id.welcome', 'zta_deferred', peer_nick=str(nick),
                         zta_status=deferred.status.value, reason=deferred.reason)
            _probes.counter('id.welcome', 'zta_deferred')
            try:
                proc._zta_capped.add(new_id.uuid)
            except Exception:
                pass
            proc._zta_standing_pending = (
                STANDING_CAPPED, policy.ddil_fallback_reputation_cap, None,
                'DDIL fallback (%s): %s' % (deferred.status.value,
                                            deferred.reason))
            return 'admit_capped'
        proc.logger.warning('ZTA: verification unavailable for %s (%s) and DDIL '
                            'fallback disabled; rejecting', nick,
                            deferred.status.value)
        return _reject(deferred.reason, status=deferred.status)
    if last_failure is not None:
        return _reject(last_failure.reason, status=last_failure.status)
    return _reject('no verifiable credential presented')


def periodic_zta_reverify(proc, queues):
    """Re-verify admitted peers' credentials, and act on what changed.

    Python's half of the C ``zta_process.c`` loop (``_reverify_peers`` +
    ``_resolve_deferred``). Until this existed, background re-verification
    was C-only: a Python node checked a credential once, at admission, and
    never again — so a credential revoked *afterwards* was never detected
    at all, and a peer admitted under the DDIL fallback stayed capped for
    ever even once the infrastructure came back. Both halves matter; the
    second is the one a disconnected deployment feels.

    It lives in IdentityProcess rather than in a ZTA process of its own
    because that is where Python's ZTA already lives (``_zta_admit``, the
    verifier cache, the peer table). C has a separate process because its
    ZTA subsystem does — see zta-python-parity.md; the split is a
    difference in structure, not in behavior.

    **Re-verification uses the admission rules, not a narrower check.** It
    walks ``_zta_match_anchors`` — the same any-of anchor walk
    ``_zta_admit`` uses — so "still proved" means "would still be admitted
    today". C's ``_reverify_peers`` asks the narrower
    ``check_revocation(hash)`` for an already-admitted peer and keeps the
    full walk for ``_resolve_deferred``; doing the full walk in both cases
    is a superset (it also catches an anchor that has since been removed
    from the policy) and cannot admit anything the narrower check would
    reject.

    **Expiry is graded more leniently than revocation**, mirroring C: a
    revoked or rejected credential is evidence of a lie, an expired one is
    evidence of a lapse, so the ceiling the peer falls under differs.
    """
    policy = zta_policy(proc)
    if not policy.enabled or policy.reverify_interval_sec <= 0:
        return
    tick = now()
    if (proc._last_zta_reverify is not None
            and (tick - proc._last_zta_reverify).total_seconds()
            < policy.reverify_interval_sec):
        return
    proc._last_zta_reverify = tick
    try:
        anchors = zta_anchor_verifiers(proc)
        if not anchors:
            return
        with proc.lock:
            if proc.peers is None:
                return
            self_uuid = str(proc.identity.uuid)
            peers = [p for p in proc.peers.all
                     if str(p.uuid) != self_uuid]
        checked = failed = resolved = 0
        for peer in peers:
            outcome = zta_reverify_one(proc, peer, anchors, policy)
            if outcome is None:
                continue        # no credential, or the verifier could not answer
            checked += 1
            status, ceiling, verified_at, reason = outcome
            if status == STANDING_FAILED:
                failed += 1
                proc.logger.warning(
                    'ZTA: re-verification FAILED for %s: %s',
                    getattr(peer, 'nickname', '?'), reason)
            elif str(peer.uuid) in proc._zta_capped:
                # A capped peer that now verifies: the DDIL condition has
                # cleared. This is the branch C's _resolve_deferred only
                # logs -- the cap it should lift was never enforced there,
                # so there was nothing to lift.
                resolved += 1
                proc._zta_capped.discard(peer.uuid)
                proc.logger.info(
                    'ZTA: deferred verification resolved for %s: VERIFIED',
                    getattr(peer, 'nickname', '?'))
            publish_zta_standing(proc, queues, peer.uuid, status, ceiling,
                                       verified_at, reason)
        if checked:
            _probes.counter('id.zta', 'reverified', str(checked))
        if failed:
            _probes.counter('id.zta', 'reverify_failed', str(failed))
        if resolved:
            _probes.counter('id.zta', 'reverify_resolved', str(resolved))
        proc.logger.debug(
            'ZTA re-verification: %d checked, %d failed, %d resolved',
            checked, failed, resolved)
    except Exception as err:
        _probes.counter('id.zta', 'reverify_exc')
        proc.report_exception(err, '_periodic_zta_reverify')


def zta_reverify_one(proc, peer, anchors, policy):
    """One peer's re-verification outcome as a standing tuple, or None.

    None means "say nothing": the peer carries no credential to check, or
    every anchor deferred (a DDIL condition, which is not a finding about
    the peer). Publishing a standing in either case would overwrite a
    verdict with the absence of one.
    """
    creds = zta_credentials(proc, peer)
    if not creds:
        return None
    mode = policy.binding_mode
    san_template = getattr(policy, 'san_uri_template', '') or ''
    worst = None       # an affirmative failure, if any anchor reported one
    unbound = False    # chained, but cannot prove entitlement to present it
    for der, binding, _issuer in creds:
        matched, _is_op, failure, deferred = zta_match_anchors(proc, 
            der, anchors)
        if not matched:
            if failure is not None and failure is not deferred:
                worst = failure
            continue
        # The chain walk does NOT consult the CRL/OCSP source -- it mirrors
        # C's x509_verify_credential, which checks the chain and expiry and
        # nothing else. Revocation has to be asked for separately, exactly
        # as the admission gate asks. Skipping this would make the whole
        # sweep blind to the one condition it exists to catch: a revoked
        # certificate still walks its chain perfectly well.
        revoked = None
        for _name, verifier, result in matched:
            rev = verifier.check_revocation(result.credential_hash)
            if rev.status is ZtaStatus.REVOKED:
                revoked = rev
                break
        if revoked is not None:
            worst = revoked
            continue
        # Genuine and unrevoked -- but is this node still entitled to
        # present it? Re-checked rather than assumed: the answer can change
        # under the node's feet when an operator tightens `binding_mode`.
        bound = identity_is_bound(
            peer, der, binding, san_template,
            operator_pubkey=getattr(peer, 'operator_pubkey', b'') or b'',
            operator_key_binding=getattr(peer, 'operator_key_binding',
                                         b'') or b'')
        if not bound and mode == BINDING_MODE_REQUIRE:
            # Unusable under this policy: the peer would not be admitted
            # today. Not forgery, so it is graded as a failure of proof
            # rather than of honesty -- but it is no longer `proved`.
            unbound = True
            continue
        if not bound and mode == BINDING_MODE_PREFER:
            # Exactly the standing admission gave it: chained, unbound,
            # capped. Re-reporting it keeps a cap that the sweep would
            # otherwise silently lift on its first pass.
            return (STANDING_CAPPED, policy.ddil_fallback_reputation_cap,
                    None, 'unbound credential (binding_mode %s)' % mode)
        # Any-of: one credential still chaining, unrevoked and bound is
        # enough, exactly as at admission.
        return (STANDING_PROVED, None, time.time(),
                're-verified against %s' % matched[0][0])
    if worst is None and unbound:
        return (STANDING_FAILED,
                min(1.0, max(0.0, 1.0 - policy.revocation_reputation_penalty
                             * 0.5)), None,
                'no bound credential under binding_mode %s' % mode)
    if worst is None:
        return None    # nobody could answer — DDIL, not a verdict
    penalty = policy.revocation_reputation_penalty
    if worst.status is ZtaStatus.EXPIRED:
        # Lapsed, not lying. Mirrors the C twin's half-weight penalty for
        # EXPIRED in _reverify_peers.
        penalty *= 0.5
    ceiling = min(1.0, max(0.0, 1.0 - penalty))
    return (STANDING_FAILED, ceiling, None,
            '%s: %s' % (worst.status.value, worst.reason))


# -- the identity hooks (_at_extension.py) ---------------------------------------
# Each answers as a node without ZTA would when the policy is disabled.

def admission_gate(proc, queues, new_id) -> str:
    """Before the welcoming committee votes: the gate's verdict, and its finding
    handed to reputation BEFORE the peer can be scored (a ceiling that arrives
    after the first commit has already let the thing it bounds happen)."""
    verdict = zta_admit(proc, new_id)
    if verdict == 'reject':
        return verdict
    publish_zta_decision(proc, queues, new_id)
    return verdict


def join_refused(proc, new_id) -> bool:
    """The ZTA half of a targeted join (doc/architecture/gateway-reputation-tree.md):
    refused when we enforce at admission, hold anchors of our own, and the
    requester proved none of them. Inert otherwise -- with no anchors of our own
    there is nothing to compare against, and refusing every requester would break
    joins for non-ZTA deployments rather than protect anything."""
    try:
        policy = zta_policy(proc)
        enforcing = bool(policy.enabled and policy.require_at_admission)
    except AttributeError:
        enforcing = False
    if not enforcing:
        return False
    own = own_zta_anchors(proc)
    if not own:
        return False
    proved = set(getattr(new_id, 'zta_anchors', None) or [])
    if proved & own:
        return False
    proc.logger.warning('Join request from %s refused: proved anchors %s share none '
                        'with ours %s', str(getattr(new_id, 'uuid', ''))[:8],
                        sorted(proved) or '[]', sorted(own))
    return True


def gateway_refused(proc, peer_uuid) -> bool:
    return not gateway_authorized(proc, peer_uuid)


def operator_credential(proc, claim, cred) -> bool:
    return is_operator_credential(proc, claim, cred)


def credential_anchored(proc, signer) -> bool:
    """Asked by REPUTATION about an evidence co-signer it never admitted: whether
    the identity it carries presents a credential that chains to one of OUR
    configured trust anchors (the doc/architecture/zta-integration.md rule,
    applied to evidence). Built from the same policy identity admits with."""
    import base64
    cred = signer.get('zta_credential') if isinstance(signer, dict) else None
    if not cred:
        return False
    try:
        der = base64.b64decode(cred)
    except Exception:
        return False
    try:
        anchors = zta_anchor_verifiers(proc)
    except ZtaPolicyError:
        raise
    except Exception:
        anchors = proc._zta_anchor_cache = []
    for _name, verifier, _is_op in anchors:
        try:
            if verifier.verify(der):
                return True
        except Exception:
            continue
    return False


def on_tick(proc, queues, tick) -> None:
    """Background re-verification (doc/architecture/zta-integration.md), asked every
    ZTA_REVERIFY_CHECK_SEC whether the POLICY's own, much longer, interval has
    elapsed. The sweep is a no-op when the policy is disabled or the interval is
    0. Mirrors the C zta_verify process loop."""
    last = proc._last_zta_reverify_check
    if last is not None and (tick - last).total_seconds() < ZTA_REVERIFY_CHECK_SEC:
        return
    proc._last_zta_reverify_check = tick
    periodic_zta_reverify(proc, queues)

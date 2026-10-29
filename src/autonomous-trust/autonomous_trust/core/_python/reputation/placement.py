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
"""Ordered placement: classic Paxos decides the chain's order
(doc/architecture/reputation.md, "Agreeing on an order").

Instance k decides what the chain holds from index k: a batch of ready items
(completed bilateral tasks and attested entries). An acceptor promises and
accepts per chain; a grant reports the value it last accepted at k, and a
proposer holding a majority of grants must carry the highest-ballot one of
those rather than its own. A decided placement is broadcast with a quorum
certificate over :func:`place_designation`, and every member writes it at k
exactly as given. Every group places its order (the half round that let a
group append entries as they completed was retired 2026-10-16).

This module is the acceptor's and learner's half. Mirrors the "Ordered
placement" section of C rep_proc.c.
"""
import json
import os
import random
import time
from queue import Full
from uuid import UUID

from ..config import Configuration, atomic_write, from_json_string, to_json_string
from ..network import Message
from ..system import CfgIds, now
from .protocol import ReputationProtocol
from .reputation import (PLACE_BATCH_MAX, ROSTER_OPS, AttestedScore,
                         Transaction, TransactionHistory, place_designation,
                         place_value_digest, roster_digest,
                         roster_members_norm, roster_n_min_norm, roster_task_id,
                         milli_to_score, validate_tx_milli)

#: Persisted acceptor state, one file per chain (doc/architecture/reputation.md).
PLACEMENT_FILE = 'reputation-placement'
#: Persisted pending pool, one file per chain: committed halves and certified
#: attestations not yet placed. Without it a restart of every holder would
#: lose them (their rounds are over; nobody re-proposes them).
POOL_FILE = 'reputation-pool'
#: Decided placements held ahead of the chain, per chain.
PLACED_AHEAD_MAX = 16
#: Equivocation records kept per chain in its evidence document, oldest
#: dropped first (R+D.md §14.1).
FORKS_MAX = 32


def _hex(value) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('ascii')
    return str(value)


def parse_ballot(obj):
    """``(n, by)`` from a ballot object, or None. `by` is the proposer's uuid,
    lowercase, which is what makes two ballots of one n distinct."""
    if not isinstance(obj, dict):
        return None
    n, by = obj.get('n'), obj.get('by')
    if not isinstance(n, int) or isinstance(n, bool) or not isinstance(by, str):
        return None
    return (n, by.lower())


def ballot_obj(ballot):
    return {'n': int(ballot[0]), 'by': str(ballot[1])}


def entry_to_dict(tx: Transaction) -> dict:
    """A placement entry on the wire. Mirrors C _place_entry_to_json."""
    d = {'task': str(tx.task_id)}
    if tx.is_roster:
        d['roster'] = {'op': tx.roster_op,
                       'uuid': None if tx.roster_uuid is None else str(tx.roster_uuid),
                       'digest': str(tx.roster_digest),
                       'members': [list(m) for m in tx.roster_members or []]}
        if tx.roster_n_min:
            d['roster']['n_min'] = int(tx.roster_n_min)
        return d
    if tx.attested:
        d.update({'attested': True, 'p1': str(tx.p1_id),
                  'p1_score_milli': int(tx.p1_score_milli),
                  'p1_channel': tx.p1_channel or '',
                  'subject': str(tx.subject_id),
                  'evidence_digest': str(tx.evidence_digest)})
        if tx.attest_scope:
            d['attest_scope'] = str(tx.attest_scope)
        if tx.attest_sigs:
            d['attest_sigs'] = {str(k): _hex(v) for k, v in tx.attest_sigs.items()}
        return d
    for side, uid, milli, chan in (('p1', tx.p1_id, tx.p1_score_milli, tx.p1_channel),
                                   ('p2', tx.p2_id, tx.p2_score_milli, tx.p2_channel)):
        d[side] = str(uid)
        d[side + '_score_milli'] = int(milli)
        if chan:
            d[side + '_channel'] = str(chan)
        cert = tx.certificate_of(uid)
        if cert:
            d[side + '_cert'] = {str(k): _hex(v) for k, v in cert.items()}
        sig = tx.half_sig_of(uid)
        if sig:
            d[side + '_sig'] = _hex(sig)
    return d


def entry_from_dict(d) -> Transaction:
    """The inverse of :func:`entry_to_dict`. Raises ValueError on anything
    malformed, including an unknown channel."""
    from uuid import UUID
    if not isinstance(d, dict):
        raise ValueError('entry is not an object')

    def _score(key):
        return validate_tx_milli(d.get(key), key)

    def _sigs(key):
        v = d.get(key)
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError('%s is not an object' % key)
        return {str(k): str(s) for k, s in v.items()}

    task = UUID(str(d['task']))
    if 'roster' in d:
        r = d['roster']
        if not isinstance(r, dict) or r.get('op') not in ROSTER_OPS \
                or not isinstance(r.get('members'), list):
            raise ValueError('malformed roster entry')
        members = r['members']
        digest = str(r.get('digest'))
        if roster_digest(members) != digest:
            raise ValueError('roster members do not match their digest')
        who = r.get('uuid')
        return Transaction(task, roster_op=r['op'],
                           roster_uuid=None if who is None else UUID(str(who)),
                           roster_digest=digest, roster_members=members,
                           roster_n_min=roster_n_min_norm(r.get('n_min')))
    if d.get('attested') is True:
        return Transaction(task, p1_id=UUID(str(d['p1'])),
                           p1_score_milli=_score('p1_score_milli'),
                           p1_channel=d.get('p1_channel') or None, attested=True,
                           subject_id=UUID(str(d['subject'])),
                           evidence_digest=str(d['evidence_digest']),
                           attest_scope=d.get('attest_scope') or None,
                           attest_sigs=_sigs('attest_sigs'))
    p1, p2 = UUID(str(d['p1'])), UUID(str(d['p2']))
    certs, half_sigs = {}, {}
    for side, uid in (('p1', p1), ('p2', p2)):
        cert = _sigs(side + '_cert')
        if cert:
            certs[str(uid)] = cert
        sig = d.get(side + '_sig')
        if sig is not None:
            if not isinstance(sig, str):
                raise ValueError('%s_sig is not a string' % side)
            half_sigs[str(uid)] = sig
    return Transaction(task, p1_id=p1, p1_score_milli=_score('p1_score_milli'),
                       p2_id=p2, p2_score_milli=_score('p2_score_milli'),
                       p1_channel=d.get('p1_channel') or None,
                       p2_channel=d.get('p2_channel') or None,
                       commit_sigs=certs or None, half_sigs=half_sigs or None)


def value_from_list(raw):
    """A value (list of entry dicts) as Transactions, or None if malformed."""
    if not isinstance(raw, list) or not 1 <= len(raw) <= PLACE_BATCH_MAX:
        return None
    try:
        return [entry_from_dict(d) for d in raw]
    except (KeyError, TypeError, ValueError):
        return None


class PlacementMixin:
    """The acceptor and learner of ordered placement, mixed into
    ReputationProcess."""

    # --- group and state ------------------------------------------------

    def _placement_path(self, chain_key: str) -> str:
        name = PLACEMENT_FILE + ('-' + chain_key if chain_key else '')
        return os.path.join(Configuration.get_cfg_dir(),
                            name + Configuration.file_ext)

    def _place_state(self, chain_key: str) -> dict:
        """This node's acceptor state for one chain: the highest ballot it has
        promised, and the value it last accepted at each open instance.
        Restored from disk on first use, so a restart cannot forget a promise
        and accept a rival's value at an instance it already voted on."""
        states = self.__dict__.setdefault('_place_states', {})
        st = states.get(chain_key)
        if st is None:
            st = {'promised': None, 'accepted': {}, 'ahead': {}}
            self._load_place_state(chain_key, st)
            states[chain_key] = st
        return st

    def _load_place_state(self, chain_key, st):
        path = self._placement_path(chain_key)
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                doc = json.load(f)
            st['promised'] = parse_ballot(doc.get('promised'))
            for k, rec in (doc.get('accepted') or {}).items():
                ballot = parse_ballot(rec.get('ballot'))
                if ballot is not None and isinstance(rec.get('value'), list):
                    st['accepted'][int(k)] = (ballot, rec['value'])
        except (OSError, ValueError, TypeError, AttributeError) as e:
            self.logger.error('Placement state %s is unreadable (%s); left in '
                              'place, and this node will promise nothing until '
                              'it is repaired', path, e)
            st['broken'] = True

    def _persist_place_state(self, chain_key, st):
        """Write the acceptor state before answering, so a promise or an
        acceptance this node sent is one it will still hold after a restart."""
        doc = {'promised': ballot_obj(st['promised']) if st['promised'] else None,
               'accepted': {str(k): {'ballot': ballot_obj(b), 'value': v}
                            for k, (b, v) in st['accepted'].items()}}
        try:
            with atomic_write(self._placement_path(chain_key)) as f:
                json.dump(doc, f)
            return True
        except (OSError, IOError, ValueError, TypeError) as e:
            self.logger.warning('Could not persist placement state: %s', e)
            return False

    # --- pool persistence -------------------------------------------------

    def _pool_path(self, chain_key: str) -> str:
        name = POOL_FILE + ('-' + chain_key if chain_key else '')
        return os.path.join(Configuration.get_cfg_dir(),
                            name + Configuration.file_ext)

    def _reset_pre_roster_chain(self, key):
        """A chain that holds entries but no roster was written before
        membership went in the chain (doc/architecture/reputation.md, "Who is
        in the group"), or by a group that did not place its order before that
        mode was retired (2026-10-16): nothing in it can be judged by a roster
        in force. It exists only in development and cohort directories, so it
        is cleared -- chain, placement state and pool -- and the group founds
        it anew (the user's calls, 2026-10-14 and 2026-10-16)."""
        chain = self._chain_for_key(key)
        if not len(chain) or chain.latest_roster() is not None:
            return False
        self.logger.warning('Placing chain %s holds %d entries and no roster: '
                            'resetting it, its placement state and its pool',
                            key or 'primary', len(chain))
        fresh = TransactionHistory(max_chain_len=chain.max_chain_len)
        if key:
            self.child_histories[key] = fresh
        else:
            self.history = fresh
        for path in (self._placement_path(key), self._pool_path(key)):
            try:
                os.remove(path)
            except OSError:
                pass
        self.__dict__.get('_place_states', {}).pop(key, None)
        return True

    def _restore_pool(self, chain_key: str):
        """Put a chain's persisted pool back, once per chain, before the
        pool is next written. Whatever was placed or tombstoned meanwhile
        stays out (record_half and pool_attested refuse it). A broken file is
        left in place and logged; the pool starts empty."""
        done = self.__dict__.setdefault('_pool_restored', set())
        if chain_key in done:
            return
        done.add(chain_key)
        path = self._pool_path(chain_key)
        if not os.path.exists(path):
            return
        chain = self._chain_for_key(chain_key)
        try:
            with open(path) as f:
                doc = json.load(f)
            held = chain.pool_from_dict(doc)
        except (OSError, ValueError, TypeError) as e:
            self.logger.error('Placement pool %s is unreadable (%s); starting '
                              'with an empty pool', path, e)
            return
        self.logger.info('Placement pool restored for chain %s: %d item(s)',
                         chain_key[:8] or 'primary', held)

    def _persist_pools(self):
        """Write each placing chain's pool when it has changed since it was
        last written. Runs on the process loop."""
        saved = self.__dict__.setdefault('_pool_saved', {})
        for key in self._chain_keys():
            self._restore_pool(key)
            chain = self._chain_for_key(key)
            mark = (id(chain), chain.pool_rev)
            if saved.get(key) == mark:
                continue
            try:
                with atomic_write(self._pool_path(key)) as f:
                    json.dump(chain.pool_to_dict(), f)
                saved[key] = mark
            except (OSError, IOError, ValueError, TypeError) as e:
                self.logger.warning('Could not persist placement pool: %s', e)

    # --- wire -----------------------------------------------------------

    def _place_send(self, queues, function, payload, to_whom):
        try:
            queues[CfgIds.network].put(
                Message(self.name, function, to_json_string(payload), to_whom,
                        from_whom=self.identity),
                block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('placement: network queue full; %s not sent', function)

    def _place_payload(self, message):
        """The payload of a placement message, with the chain it is for, or
        None when it is malformed, unverified, or for a chain that does not
        place."""
        if not message.verified:
            self.logger.warning('Rejecting unverified %s from %s',
                                message.function, message.from_whom)
            return None
        try:
            payload = from_json_string(message.obj)
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        k = payload.get('k')
        if not isinstance(k, int) or isinstance(k, bool) or k < 0:
            return None
        group = payload.get('group') or None
        key = self._chain_key(group)
        return payload, key, self._chain_for_key(key), group

    def _place_deciders_ok(self, key, k, ballot) -> bool:
        """Do this node and the proposer both decide instance `k`? Once the
        chain holds a roster only its members promise, accept or propose
        there (doc/architecture/reputation.md, "Who is in the group"). An
        instance past our next is judged by our latest roster: the position
        check refuses it anyway."""
        members = self._place_members(key, k)
        return str(self.identity.uuid).lower() in members and ballot[1] in members

    def _from_proposer(self, message, ballot) -> bool:
        sender = getattr(message.from_whom, 'uuid', None)
        return sender is not None and str(sender).lower() == ballot[1]

    def _place_nack(self, queues, message, payload, chain, st, why):
        self.logger.debug('Placement %d from %s refused: %s', payload['k'],
                          getattr(message.from_whom, 'nickname', '?'), why)
        nack = {'group': payload.get('group') or '', 'k': payload['k'],
                'ballot': payload.get('ballot'), 'next': chain.next_index}
        if st['promised'] is not None:
            nack['promised'] = ballot_obj(st['promised'])
        self._place_send(queues, ReputationProtocol.place_nack, nack,
                         message.from_whom)

    def _place_position_ok(self, queues, message, payload, chain, st) -> bool:
        """Instance k is open here only once everything below it is applied,
        and only on the same prefix: the head the proposer extends must be
        ours. Otherwise refuse, and catch up when we are the one behind."""
        k = payload['k']
        if k != chain.next_index:
            self._place_nack(queues, message, payload, chain, st,
                             'at %d, our next is %d' % (k, chain.next_index))
            if k > chain.next_index:
                try:
                    self._request_update(
                        queues, key=self._chain_key(payload.get('group') or None))
                except Full:
                    pass
            return False
        if str(payload.get('head') or '') != _hex(chain.head_hash):
            self._place_nack(queues, message, payload, chain, st,
                             'extends another head')
            return False
        return True

    # --- acceptor -------------------------------------------------------

    def handle_place_request(self, queues, message):
        if message.function != ReputationProtocol.place_request:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, _group = got
        ballot = parse_ballot(payload.get('ballot'))
        if ballot is None or not self._from_proposer(message, ballot):
            return True
        st = self._place_state(key)
        if st.get('broken') or not self._place_deciders_ok(key, payload['k'], ballot):
            return True
        self._note_place_heard(key, payload['k'])
        if not self._place_position_ok(queues, message, payload, chain, st):
            return True
        if st['promised'] is not None and ballot <= st['promised']:
            self._place_nack(queues, message, payload, chain, st, 'outranked')
            return True
        st['promised'] = ballot
        if not self._persist_place_state(key, st):
            return True
        grant = {'group': payload.get('group') or '', 'k': payload['k'],
                 'ballot': ballot_obj(ballot)}
        held = st['accepted'].get(payload['k'])
        if held is not None:
            grant['accepted'] = {'ballot': ballot_obj(held[0]), 'value': held[1]}
        self._place_send(queues, ReputationProtocol.place_grant, grant,
                         message.from_whom)
        return True

    def _place_value_ok(self, entries, chain, group,
                        config_check=True) -> 'str | None':
        """Why this value cannot be placed on `chain` now, or None when it
        can. Checked against this node's own prefix and its own view of the
        group, before accepting, so a decided value is valid by construction
        and its write never needs checking. A proposer carrying a value
        another member accepted passes `config_check=False`: whether a
        declared N_min matches each acceptor's configuration is for the
        acceptors to say (RD_13.2 plan §0.4, call 9)."""
        if any(tx.is_roster for tx in entries):
            return self._roster_value_ok(entries, chain, self._chain_key(group),
                                         config_check)
        if not self._founded(chain):
            return 'nothing is placed before the genesis'
        tasks = [str(tx.task_id).lower() for tx in entries]
        if tasks != sorted(tasks) or len(set(tasks)) != len(tasks):
            return 'not one of each task, by task id'
        for tx in entries:
            if chain._placed(tx.task_id) or tx.task_id in chain._evicted_task_ids:
                return 'task %s is already held' % str(tx.task_id)[:8]
            if tx.attested:
                if not chain._attested_well_formed(tx):
                    return 'malformed attestation'
                att = AttestedScore.of_transaction(tx, str(group or ''))
                if not self._attest_quorum_met(att, tx.attest_sigs or {}):
                    return 'attestation %s lacks its quorum' % str(tx.task_id)[:8]
                if self._attest_resident(chain, att):
                    return 'attestation %s is over its rate cap' % str(tx.task_id)[:8]
                continue
            if tx.p1_id is None or tx.p2_id is None or tx.p1_id == tx.p2_id:
                return 'entry %s is not bilateral' % str(tx.task_id)[:8]
            if str(tx.p1_id).lower() > str(tx.p2_id).lower():
                return 'entry %s halves out of order' % str(tx.task_id)[:8]
            for uid, score, chan in ((tx.p1_id, tx.p1_score_milli, tx.p1_channel),
                                     (tx.p2_id, tx.p2_score_milli, tx.p2_channel)):
                if not self._commit_cert_ok(uid, tx.task_id, score, chan,
                                            tx.certificate_of(uid), group):
                    return 'half %s of %s is not certified' % (
                        str(uid)[:8], str(tx.task_id)[:8])
            who = self._entry_halves_signed(tx, chain)
            if who is not None:
                return 'half %s of %s is not signed by its scorer' % (
                    who[:8], str(tx.task_id)[:8])
        return None

    def handle_place(self, queues, message):
        if message.function != ReputationProtocol.place:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, group = got
        ballot = parse_ballot(payload.get('ballot'))
        if ballot is None or not self._from_proposer(message, ballot):
            return True
        st = self._place_state(key)
        if st.get('broken') or not self._place_deciders_ok(key, payload['k'], ballot):
            return True
        self._note_place_heard(key, payload['k'])
        if not self._place_position_ok(queues, message, payload, chain, st):
            return True
        if st['promised'] is not None and ballot < st['promised']:
            self._place_nack(queues, message, payload, chain, st, 'outranked')
            return True
        raw = payload.get('value')
        entries = value_from_list(raw)
        if entries is None:
            return True
        why = self._place_value_ok(entries, chain, group if key else None)
        if why is not None:
            self.logger.warning('Not accepting placement %d from %s: %s',
                                payload['k'], getattr(message.from_whom, 'nickname', '?'),
                                why)
            return True
        k = payload['k']
        st['promised'] = ballot
        st['accepted'] = {i: rec for i, rec in st['accepted'].items() if i >= k}
        st['accepted'][k] = (ballot, raw)
        if not self._persist_place_state(key, st):
            return True
        digest = place_value_digest(entries, k)
        try:
            sig = self._detached_sig(self.identity, place_designation(
                k, chain.head_hash, digest))
        except Exception:
            self.logger.error('handle_place: cannot sign; not accepting')
            return True
        accepted = {'group': payload.get('group') or '', 'k': k,
                    'ballot': ballot_obj(ballot),
                    'digest': _hex(digest), 'sig': sig}
        mine = roster_n_min_norm(getattr(self, 'N_MIN', None))
        if mine is not None:
            accepted['n_min'] = mine      # our report (see "the declared N_min")
        self._place_send(queues, ReputationProtocol.place_accepted, accepted,
                         message.from_whom)
        return True

    # --- learner --------------------------------------------------------

    def _placement_certified(self, chain, k, entries, sigs, group,
                             roster=..., prev=None) -> bool:
        """Does `sigs` certify this value at k, after OUR head? A strict
        majority of the roster in force for k (doc/architecture/reputation.md,
        "Who is in the group"), verified with the keys it records, must have
        signed its :func:`place_designation`; a genesis, every member it
        lists. Before a roster there is nothing else to learn."""
        digest = place_value_digest(entries, k)
        desig = place_designation(k, chain.head_hash if prev is None else prev,
                                  digest)
        if roster is ...:
            roster = chain.roster_at(k)
        genesis = self._genesis_of(entries)
        if roster is None and genesis is not None:
            # A genesis is decided by every member it lists.
            return len(self._verified_cosigners(desig, sigs, genesis)) == \
                len(genesis.roster_members or ())
        if roster is not None:
            return len(self._verified_cosigners(desig, sigs, roster)) >= \
                len(roster.roster_members or ()) // 2 + 1
        return False            # nothing but a genesis before the roster

    # --- equivocation (R+D.md §14.1) ----------------------------------------
    #
    # Two certificates for different values at one index mean two quorums of
    # the roster signed both, and the members in both signed twice. We keep
    # ours either way. The record holds both certificates, so this node can
    # prove it later; it is never sent and never scored (the user's calls,
    # 2026-10-21, D3 B and D4 B).

    def _fork_records(self, key) -> list:
        return list(getattr(self, '_forks', {}).get(key, ()))

    def _load_fork_records(self, key, doc):
        """Take back the records an evidence document holds for chain `key`."""
        raw = doc.get('forks') if isinstance(doc, dict) else None
        if not isinstance(raw, list):
            return
        keep = [dict(r) for r in raw if isinstance(r, dict)
                and isinstance(r.get('index'), int)
                and isinstance(r.get('ours'), dict)
                and isinstance(r.get('theirs'), dict)]
        if not hasattr(self, '_forks'):
            self._forks = {}
        self._forks[key] = keep[-FORKS_MAX:]

    def _fork_cert(self, chain, k, entries, sigs, prev) -> dict:
        """One side of an equivocation: the placement at `k` after the entry
        whose hash is `prev`, its value digest, its signatures, and who among
        them verifies against the roster in force for `k` (our live view
        while the chain holds none)."""
        digest = place_value_digest(entries, k)
        desig = place_designation(k, prev or b'', digest)
        roster = chain.roster_at(k)
        return {'k': int(k), 'prev': _hex(prev), 'digest': _hex(digest),
                'sigs': {str(u).lower(): _hex(v) for u, v in sigs.items()},
                'signers': sorted(self._verified_cosigners(desig, sigs, roster))}

    def _own_fork_cert(self, chain, f):
        """Our own certificate for the placement holding index `f`, or None
        when it is not resident in full."""
        for k, entries, sigs in chain.placement_batches(list(chain._chain)):
            if entries and k <= f < k + len(entries):
                return self._fork_cert(chain, k, entries, sigs,
                                       entries[0].prev_hash)
        return None

    def _note_equivocation(self, key, f, source, sender, ours, theirs):
        """Keep one equivocation record for chain `key` and persist it."""
        if ours is None or theirs is None or ours['digest'] == theirs['digest']:
            return
        if not hasattr(self, '_forks'):
            self._forks = {}
        held = self._forks.setdefault(key, [])
        if any(r.get('index') == f and r['ours'].get('digest') == ours['digest']
               and r['theirs'].get('digest') == theirs['digest'] for r in held):
            return
        both = sorted(set(ours['signers']) & set(theirs['signers']))
        held.append({'index': int(f), 'source': source,
                     'from': None if sender is None else str(sender).lower(),
                     'at': int(time.time()), 'ours': ours, 'theirs': theirs,
                     'both': both})
        del held[:-FORKS_MAX]
        self.logger.error(
            'equivocation recorded on chain %s at index %d (%s): %d member(s) '
            'signed both values', key or 'primary', f, source, len(both))
        self._persist_history(key)

    def _record_catchup_equivocation(self, key, chain, seg, f, sender):
        """Catch-up returned EQUIVOCATION at `f`: record our certificate and
        the segment's."""
        theirs = None
        for k, entries, sigs in chain.placement_batches(seg):
            if entries and k <= f < k + len(entries):
                theirs = self._fork_cert(chain, k, entries, sigs,
                                         entries[0].prev_hash)
                break
        self._note_equivocation(key, f, 'catchup', sender,
                                self._own_fork_cert(chain, f), theirs)

    def _check_placed_equivocation(self, key, chain, k, entries, sigs, sender):
        """A `placed` for an index we already hold. The same value is a late
        duplicate. A different value whose certificate verifies after our own
        entry at k-1 is an equivocation, recorded at the first index where the
        two differ."""
        held = {t.index: t for t in chain._chain if t.index is not None}
        ours = [held.get(i) for i in range(k, k + len(entries))]
        if any(t is None for t in ours):
            return
        if place_value_digest(ours, k) == place_value_digest(entries, k):
            return
        before = held.get(k - 1)
        prev = b'' if k == 0 else (None if before is None else before.entry_hash())
        if prev is None or not self._placement_certified(
                chain, k, entries, sigs, None, prev=prev):
            return
        f = next((k + i for i in range(len(entries))
                  if place_value_digest([ours[i]], k + i)
                  != place_value_digest([entries[i]], k + i)), k)
        self._note_equivocation(key, f, 'placed', sender,
                                self._own_fork_cert(chain, f),
                                self._fork_cert(chain, k, entries, sigs, prev))

    def _apply_placement(self, chain, key, k, entries, sigs, group) -> bool:
        if not self._placement_certified(chain, k, entries, sigs, group):
            self.logger.warning('Refusing placement %d: its certificate does '
                                'not meet our quorum', k)
            return False
        # A placement certificate is the majority's word, and so is every
        # commit certificate in it; a scorer's own signature is not
        # (R+D.md §14.2). An entry missing one is refused whatever signed
        # the placement.
        for tx in entries:
            who = self._entry_halves_signed(tx, chain)
            if who is not None:
                self.logger.warning(
                    'Refusing placement %d: task %s carries no valid signature '
                    'by %s over its own half', k, str(tx.task_id)[:8], who[:8])
                return False
        chain.apply_placed(k, entries, sigs)
        me = str(self.identity.uuid)
        for i, tx in enumerate(entries):
            if not tx.is_roster and not tx.attested and len(tx) == 2:
                # The line a commit used to log when it completed an entry;
                # under ordered placement an entry is completed here (cohorts
                # and operators watch for it). Mirrors C.
                self.logger.info('task %s is bilateral (index %d)', tx.task_id, k + i)
            if tx.attested:
                # What _commit_attestation does for a chain that does not
                # place: a checkpoint soon, so the entry is archived before a
                # busy chain can evict it, and the line cohorts watch for.
                soon = now().timestamp() + self.ATTEST_CHECKPOINT_SEC
                if self._next_checkpoint_at > soon:
                    self._next_checkpoint_at = soon
                self.logger.info(
                    'Attested score committed: verifier=%s subject=%s '
                    'score=%.2f channel=%s signers=%d (index %d)',
                    str(tx.p1_id)[:8], str(tx.subject_id)[:8],
                    milli_to_score(tx.p1_score_milli), tx.p1_channel,
                    len(chain.attest_certs.get(tx.task_id) or {}), k + i)
            self._fold_committed_tx(tx.task_id, chain)
            for uid in (tx.p1_id, tx.p2_id, tx.subject_id if tx.attested else None):
                if uid is None:
                    continue
                if str(uid) == me:
                    self.awaiting_commit.pop(str(tx.task_id), None)
                else:
                    self._note_interaction(uid)
        st = self._place_state(key)
        st['accepted'] = {i: rec for i, rec in st['accepted'].items()
                          if i >= chain.next_index}
        self.logger.info('Placed %d entr%s at %d on chain %s (next %d)',
                         len(entries), 'y' if len(entries) == 1 else 'ies',
                         k, key or 'primary', chain.next_index)
        return True

    def handle_placed(self, queues, message):
        if message.function != ReputationProtocol.placed:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, group = got
        entries = value_from_list(payload.get('value'))
        sigs = payload.get('sigs')
        if entries is None or not isinstance(sigs, dict):
            return True
        k = payload['k']
        if k < chain.next_index:
            self._check_placed_equivocation(
                key, chain, k, entries, sigs,
                getattr(message.from_whom, 'uuid', None))
            return True
        st = self._place_state(key)
        if k > chain.next_index:
            # Ahead of us: hold it until the chain reaches k, and catch up.
            if len(st['ahead']) < PLACED_AHEAD_MAX or k in st['ahead']:
                st['ahead'][k] = (entries, sigs)
            try:
                self._request_update(queues, key=key)
            except Full:
                pass
            return True
        if not self._apply_placement(chain, key, k, entries, sigs,
                                     group if key else None):
            return True
        sender = getattr(message.from_whom, 'uuid', None)
        if sender is not None:
            v = self._place_vars()
            v['_placers'][key] = str(sender).lower()
            v['_place_lead'].pop(key, None)
        self._apply_ahead(key, chain, group if key else None)
        return True

    def _apply_ahead(self, key, chain, group):
        """Write the decided placements held ahead of the chain that now
        follow it, in order, and forget any it has passed."""
        st = self._place_state(key)
        while chain.next_index in st['ahead']:
            more, more_sigs = st['ahead'].pop(chain.next_index)
            if not self._apply_placement(chain, key, chain.next_index, more,
                                         more_sigs, group):
                break
        st['ahead'] = {i: rec for i, rec in st['ahead'].items()
                       if i >= chain.next_index}

    # --- proposer -------------------------------------------------------
    #
    # Who proposes: the node that placed the previous instance on this chain
    # leads the next one, so in a quiet group one node drives every placement
    # and nobody duels. Every other member with ready items waits
    # PLACE_READY_WAIT, plus PLACE_RANK_STEP per place it holds in this
    # instance's ranking, before taking over; hearing anyone else work on the
    # instance resets that wait. A round that stalls for PLACE_ROUND_TIMEOUT
    # is dropped, and a refused one backs off a random interval, so rival
    # proposers spread out instead of colliding again.
    #
    # The leader skips the first phase (Multi-Paxos). A promise is for the
    # whole chain, not one instance, and an acceptor only accepts at its own
    # next index, so the majority that promised our ballot at k-1 had
    # accepted nothing at k, and cannot accept a lower ballot there now. Our
    # ballot therefore still carries k, and we send `place` at once. A member
    # that promised a higher ballot since refuses it, and a refused or stalled
    # round drops the lead: the next one asks again.

    PLACE_READY_WAIT = 3.0
    PLACE_RANK_STEP = 0.3
    PLACE_ROUND_TIMEOUT = 5.0
    PLACE_BACKOFF = (0.5, 2.0)

    def _place_vars(self):
        d = self.__dict__
        if '_place_rounds' not in d:
            d['_place_rounds'] = {}       # chain key -> our open round
            d['_place_ready_since'] = {}  # chain key -> (k, when ready items appeared)
            d['_place_heard'] = {}        # chain key -> (k, when we last heard a round)
            d['_placers'] = {}            # chain key -> uuid str of the last placer
            d['_place_backoff'] = {}      # chain key -> do not start before
            d['_place_seen_n'] = 0        # highest ballot n seen anywhere
            d['_place_lead'] = {}         # chain key -> (k, ballot) we may place at unasked
        return d

    def _place_roster(self, key, k):
        """The roster in force for instance `k` of chain `key`, or None while
        the chain holds none (doc/architecture/reputation.md, "Who is in the
        group")."""
        return self._chain_for_key(key).roster_at(k)

    def _place_members(self, key, k=None):
        """The members who decide instance `k` of chain `key`, as uuid strs:
        those of the roster in force for it, or, while there is none (or k is
        not given), this node and the other members of the chain's group."""
        if k is not None:
            roster = self._place_roster(key, k)
            if roster is not None:
                return [u for u, _key in roster.roster_members or ()]
        grp = self._group_by_uuid(key) if key else None
        peers = self._members_of_group(grp) if key else self._roster_peers()
        return [str(self.identity.uuid).lower()] + [str(p.uuid).lower() for p in peers]

    # --- who is in the group (doc/architecture/reputation.md) ---------------
    #
    # The members deciding instance k are those of the roster logged before
    # it. A placing chain's first entry is a genesis roster, decided by every
    # member it lists; after that, each member it does not yet list is added
    # by one roster entry, decided by a majority of the roster before it, and
    # a roster about to leave the resident window is restated. Rosters only
    # grow (the user's call, 2026-10-14). A roster entry is placed alone and
    # ahead of any ready item.

    def _live_roster(self, key) -> 'list[list[str]]':
        """This node and the live members of the chain's group, each with its
        signing key, as a roster member list (sorted)."""
        from nacl.encoding import HexEncoder
        grp = self._group_by_uuid(key) if key else None
        peers = self._members_of_group(grp) if key else self._roster_peers()
        out = []
        for ident in [self.identity] + list(peers):
            try:
                out.append([str(ident.uuid).lower(), ident.signature.public.encode(
                    encoder=HexEncoder).decode('ascii')])
            except AttributeError:
                continue
        return [list(m) for m in roster_members_norm(out)]

    def _roster_item(self, key, chain) -> 'Transaction | None':
        """The roster entry this node would place next on `chain`, or None:
        a genesis of its live view on an empty chain, an add of the first
        live member the roster in force lacks, or a restatement of a roster
        half a window old."""
        live = self._live_roster(key)
        roster = chain.latest_roster()
        if roster is None:
            if chain.next_index != 0 or len(chain) or len(live) < 2:
                return None
            d = roster_digest(live)
            return Transaction(roster_task_id(None, 'genesis', None, d),
                               roster_op='genesis', roster_digest=d,
                               roster_members=live)
        have = dict(map(tuple, roster.roster_members or ()))
        n_min = roster.roster_n_min
        missing = sorted(u for u, _k in live if u not in have)
        if missing:
            who = missing[0]
            members = list(map(list, roster.roster_members)) + [[who, dict(live)[who]]]
            d = roster_digest(members)
            return Transaction(roster_task_id(roster.task_id, 'add', who, d, n_min),
                               roster_op='add', roster_uuid=UUID(who),
                               roster_digest=d, roster_members=members,
                               roster_n_min=n_min)
        target = self._n_min_majority(key, roster)
        if target is not ... and target != n_min:
            # A strict majority of the roster reports another N_min: restate
            # the roster declaring it, whatever our own configuration.
            n_min = target
        elif roster.index is None or \
                chain.next_index - roster.index < chain.max_chain_len // 2:
            return None
        d = roster.roster_digest
        return Transaction(roster_task_id(roster.task_id, 'restate', None, d, n_min),
                           roster_op='restate', roster_digest=d,
                           roster_members=roster.roster_members,
                           roster_n_min=n_min)

    # --- the declared N_min (RD_13.2 plan §0.4) ---------------------------
    #
    # A roster entry may declare the group's N_min, and with it the F the
    # certificate rounds are sized for. A genesis declares none. Each member
    # reports its configured value in every place_accepted, and the member
    # leading a placement restates the roster with value X once a strict
    # majority of the roster in force has reported X, whatever it is
    # configured for itself: a leader proposing its own value could have it
    # accepted by itself alone, and every later proposer at that index would
    # then have to carry a value most acceptors refuse. An acceptor takes a
    # value only if it is the one in force or the one it is configured for.

    def _n_min_reports(self, key) -> dict:
        return self.__dict__.setdefault('_place_n_min_seen', {}).setdefault(key, {})

    def _n_min_majority(self, key, roster):
        """The N_min a strict majority of `roster`'s members reports (this
        node's configuration standing for its own report), or ... when no
        value has one."""
        me = str(self.identity.uuid).lower()
        seen = dict(self._n_min_reports(key))
        seen[me] = roster_n_min_norm(getattr(self, 'N_MIN', None))
        listed = [u for u, _k in roster.roster_members or ()]
        counts = {}
        for u in listed:
            if u in seen:
                counts[seen[u]] = counts.get(seen[u], 0) + 1
        for value, n in counts.items():
            if n >= len(listed) // 2 + 1:
                return value
        return ...

    def _roster_value_ok(self, entries, chain, key,
                         config_check=True) -> 'str | None':
        """Why a value holding a roster entry cannot be accepted on `chain`
        now, or None when it can (the acceptor's rules for roster entries).
        A declared N_min must be the one in force (none before the genesis)
        or, with `config_check`, the one this node is configured for."""
        if len(entries) != 1:
            return 'a roster entry is placed alone'
        tx = entries[0]
        live = dict(map(tuple, self._live_roster(key)))
        members = dict(map(tuple, tx.roster_members or ()))
        if not members or roster_digest(tx.roster_members) != tx.roster_digest:
            return 'roster members do not match their digest'
        me = str(self.identity.uuid).lower()
        roster = chain.latest_roster()
        in_force = None if roster is None else roster.roster_n_min
        mine = roster_n_min_norm(getattr(self, 'N_MIN', None))
        n_min = tx.roster_n_min
        if n_min != in_force and config_check and n_min != mine:
            return 'a declared n_min of %s, ours is %s and %s is in force' % (
                n_min, mine, in_force)
        if tx.roster_op == 'genesis':
            if roster is not None or chain.next_index != 0:
                return 'genesis on a chain that has one'
            if me not in members:
                return 'a genesis that leaves us out'
            if any(live.get(u) != k for u, k in members.items()):
                return 'a genesis naming a member we do not see'
            want = roster_task_id(None, 'genesis', None, tx.roster_digest, n_min)
        elif roster is None:
            return 'a roster change with no roster in force'
        elif tx.roster_op == 'add':
            have = dict(map(tuple, roster.roster_members or ()))
            who = None if tx.roster_uuid is None else str(tx.roster_uuid).lower()
            if who is None or who in have:
                return 'an add of nobody new'
            if members != dict(have, **{who: members.get(who)}):
                return 'an add that changes more than one member'
            if live.get(who) != members.get(who):
                return 'an add of a member we do not see'
            if n_min != in_force:
                return 'an add that changes the declared n_min'
            want = roster_task_id(roster.task_id, 'add', who, tx.roster_digest, n_min)
        else:
            if tx.roster_digest != roster.roster_digest:
                return 'a restatement that changes the roster'
            if n_min == in_force and (roster.index is None or
                                      chain.next_index - roster.index
                                      < chain.max_chain_len // 2):
                return 'a restatement too early'
            want = roster_task_id(roster.task_id, 'restate', None,
                                  tx.roster_digest, n_min)
        if str(tx.task_id) != str(want):
            return 'a roster entry with the wrong task id'
        return None

    @staticmethod
    def _founded(chain) -> bool:
        """Has `chain` a roster in force? Nothing but a genesis is placed,
        accepted or learned before."""
        return chain.latest_roster() is not None

    def _genesis_of(self, entries):
        """The genesis roster entry a value is, or None."""
        if entries and len(entries) == 1 and entries[0].is_roster \
                and entries[0].roster_op == 'genesis':
            return entries[0]
        return None

    def _place_majority(self, key, k, group) -> int:
        """How many signatures, the proposer's own included, decide instance
        `k`: a strict majority of the roster in force for it, or of the live
        view while there is none."""
        roster = self._place_roster(key, k)
        if roster is not None:
            return len(roster.roster_members or ()) // 2 + 1
        chain = self._chain_for_key(key)
        if k == 0 and chain.next_index == 0 and not len(chain):
            # The genesis: every member it will list.
            return len(self._live_roster(key))
        return self._round_quorum(group) + 1

    def _place_rank(self, key, k) -> 'int | None':
        """Where this node stands in instance k's takeover order: the members
        by blake2b(uuid|k), so every node reaches the same order and it changes
        from one instance to the next. None when it is not a member."""
        import hashlib
        me = str(self.identity.uuid).lower()
        members = self._place_members(key, k)
        if me not in members:
            return None
        order = sorted(members, key=lambda u: hashlib.blake2b(
            ('%s|%d' % (u, k)).encode(), digest_size=16).hexdigest())
        return order.index(me)

    def _place_target(self, key):
        """Where a round's broadcast goes: the chain's group."""
        return (self._group_by_uuid(key) if key else None) or self.group

    def _note_place_heard(self, key, k):
        self._place_vars()['_place_heard'][key] = (k, time.monotonic())

    def _maybe_place(self, queues, present=None):
        """Start a placement round on any chain that has ready items and whose
        next instance is ours to propose now. Runs on the process loop."""
        v = self._place_vars()
        clock = time.monotonic()
        for key in self._chain_keys():
            group = key or None
            chain = self._chain_for_key(key)
            k = chain.next_index
            rnd = v['_place_rounds'].get(key)
            if rnd is not None and rnd['k'] != k:
                v['_place_rounds'].pop(key, None)
                rnd = None
            if rnd is not None:
                if clock - rnd['started'] > self.PLACE_ROUND_TIMEOUT:
                    v['_place_rounds'].pop(key, None)
                    v['_place_lead'].pop(key, None)
                    v['_place_backoff'][key] = clock + random.uniform(*self.PLACE_BACKOFF)
                continue
            if clock < v['_place_backoff'].get(key, 0.0):
                continue
            pending = self._roster_item(key, chain) is not None or (
                bool(chain.ready_items(1)) and self._founded(chain))
            if not pending:
                v['_place_ready_since'].pop(key, None)
                continue
            since = v['_place_ready_since'].get(key)
            if since is None or since[0] != k:
                since = (k, clock)
                v['_place_ready_since'][key] = since
            heard = v['_place_heard'].get(key)
            if heard is not None and heard[0] == k \
                    and clock - heard[1] < self.PLACE_ROUND_TIMEOUT:
                continue
            me = str(self.identity.uuid).lower()
            placer = v['_placers'].get(key)
            rank = self._place_rank(key, k)
            if rank is None:
                continue                # not a member of the roster in force
            if placer is not None and placer not in self._place_members(key, k):
                placer = None
            leader = placer == me if placer is not None else rank == 0
            wait = 0.0 if leader else self.PLACE_READY_WAIT + rank * self.PLACE_RANK_STEP
            if clock - since[1] < wait:
                continue
            lead = v['_place_lead'].get(key)
            st = self._place_state(key)
            if leader and lead is not None and lead[0] == k \
                    and st['promised'] == lead[1] and k not in st['accepted'] \
                    and not st.get('broken'):
                self._place_unasked(queues, key, chain, lead[1])
            else:
                v['_place_lead'].pop(key, None)
                self._start_place_round(queues, key, chain)

    def _place_unasked(self, queues, key, chain, ballot):
        """Lead instance k under the ballot a majority promised us at k-1:
        straight to `place`, with our own ready items."""
        group = key or None
        entries = self._own_place_value(chain, key, group)
        if not entries:
            return
        rnd = {'k': chain.next_index, 'ballot': ballot, 'head': chain.head_hash,
               'grants': {}, 'value': None, 'entries': None, 'accepts': {},
               'started': time.monotonic()}
        self._place_vars()['_place_rounds'][key] = rnd
        self._send_place(queues, key, chain, rnd, entries,
                         [entry_to_dict(e) for e in entries])
        self.logger.debug('Placing %d under %s without asking', rnd['k'], ballot)

    def _start_place_round(self, queues, key, chain):
        v = self._place_vars()
        st = self._place_state(key)
        if st.get('broken'):
            return
        me = str(self.identity.uuid).lower()
        n = max(int(time.time() * 1000), v['_place_seen_n'] + 1)
        if st['promised'] is not None and st['promised'][0] >= n:
            n = st['promised'][0] + 1
        v['_place_seen_n'] = n
        ballot = (n, me)
        # Our own promise first: we are one of the acceptors.
        st['promised'] = ballot
        if not self._persist_place_state(key, st):
            return
        k = chain.next_index
        held = st['accepted'].get(k)
        v['_place_rounds'][key] = {
            'k': k, 'ballot': ballot, 'head': chain.head_hash,
            'grants': {me: held}, 'value': None, 'entries': None,
            'accepts': {}, 'started': time.monotonic()}
        self._place_send(queues, ReputationProtocol.place_request,
                         {'group': key, 'k': k, 'ballot': ballot_obj(ballot),
                          'head': _hex(chain.head_hash)},
                         self._place_target(key))
        self.logger.debug('Asking for placement %d under %s', k, ballot)

    def _place_round_for(self, payload, key):
        rnd = self._place_vars()['_place_rounds'].get(key)
        ballot = parse_ballot(payload.get('ballot'))
        if rnd is None or rnd['k'] != payload['k'] or ballot != rnd['ballot']:
            return None
        return rnd

    def _place_voter(self, message, key, k=None):
        """The member a reply about instance `k` is from, or None for one
        who does not decide it."""
        sender = getattr(message.from_whom, 'uuid', None)
        if sender is None:
            return None
        voter = str(sender).lower()
        return voter if voter in self._place_members(key, k) else None

    def handle_place_grant(self, queues, message):
        if message.function != ReputationProtocol.place_grant:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, group = got
        rnd = self._place_round_for(payload, key)
        voter = self._place_voter(message, key, payload['k'])
        if rnd is None or voter is None or rnd['value'] is not None:
            return True
        held = None
        acc = payload.get('accepted')
        if isinstance(acc, dict):
            b = parse_ballot(acc.get('ballot'))
            if b is not None and isinstance(acc.get('value'), list):
                held = (b, acc['value'])
        rnd['grants'][voter] = held
        if len(rnd['grants']) < self._place_majority(key, rnd['k'],
                                                     group if key else None):
            return True
        # A majority promised. Carry the highest-ballot value any of them
        # accepted at k, or, if none did, our own ready items.
        reported = [g for g in rnd['grants'].values() if g is not None]
        if reported:
            raw = max(reported, key=lambda g: g[0])[1]
            entries = value_from_list(raw)
            if entries is None or self._place_value_ok(
                    entries, chain, group if key else None,
                    config_check=False) is not None:
                self.logger.warning('Placement %d: the value to carry is not '
                                    'valid here; dropping the round', rnd['k'])
                self._place_vars()['_place_rounds'].pop(key, None)
                return True
        else:
            entries = self._own_place_value(chain, key, group if key else None)
            if not entries:
                self._place_vars()['_place_rounds'].pop(key, None)
                return True
            raw = [entry_to_dict(e) for e in entries]
        self._send_place(queues, key, chain, rnd, entries, raw)
        return True

    def _own_place_value(self, chain, key, group):
        """Our ready items, as a value to place: only items an acceptor will
        take. One it would refuse (a half whose certificate falls short of our
        quorum, say) leaves the pool, or it would sink every round that
        carries it."""
        item = self._roster_item(key, chain)
        if item is not None:
            return [item]
        if not self._founded(chain):
            return []                   # nothing is placed before the genesis
        entries = []
        for e in chain.ready_items():
            why = self._place_value_ok([e], chain, group)
            if why is None:
                entries.append(e)
            else:
                chain.pool_drop(e.task_id)
                self.logger.warning('Placement: dropping %s from the pool: '
                                    '%s', str(e.task_id)[:8], why)
        return entries

    def _send_place(self, queues, key, chain, rnd, entries, raw):
        """Accept `raw` at the round's instance ourselves, then ask the group
        to: phase 2 of the round."""
        k, ballot = rnd['k'], rnd['ballot']
        st = self._place_state(key)
        if st['promised'] is not None and ballot < st['promised']:
            self._place_vars()['_place_rounds'].pop(key, None)
            return
        st['accepted'] = {i: r for i, r in st['accepted'].items() if i >= k}
        st['accepted'][k] = (ballot, raw)
        if not self._persist_place_state(key, st):
            return
        digest = place_value_digest(entries, k)
        rnd['value'], rnd['entries'], rnd['digest'] = raw, entries, digest
        me = str(self.identity.uuid).lower()
        rnd['accepts'][me] = self._detached_sig(
            self.identity, place_designation(k, rnd['head'], digest))
        self._place_send(queues, ReputationProtocol.place,
                         {'group': key, 'k': k, 'ballot': ballot_obj(ballot),
                          'head': _hex(rnd['head']), 'value': raw},
                         self._place_target(key))

    def handle_place_accepted(self, queues, message):
        if message.function != ReputationProtocol.place_accepted:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, group = got
        rnd = self._place_round_for(payload, key)
        voter = self._place_voter(message, key, payload['k'])
        if voter is not None:
            # The member's N_min report, from any acceptance it sends: a round
            # closes on its majority, and the reports of the rest would go
            # stale. A hint only; each acceptor holds its own configuration.
            try:
                self._n_min_reports(key)[voter] = roster_n_min_norm(payload.get('n_min'))
            except ValueError:
                self._n_min_reports(key).pop(voter, None)
        if rnd is None or voter is None or rnd['value'] is None:
            return True
        if str(payload.get('digest') or '') != _hex(rnd['digest']):
            return True
        desig = place_designation(rnd['k'], rnd['head'], rnd['digest'])
        genesis = self._genesis_of(rnd['entries'])
        deciders = self._place_roster(key, rnd['k']) or genesis
        if not self._verify_cosignature(desig, voter, payload.get('sig'), deciders):
            return True
        rnd['accepts'][voter] = payload['sig']
        need = (len(genesis.roster_members) if genesis is not None
                and self._place_roster(key, rnd['k']) is None
                else self._place_majority(key, rnd['k'], group if key else None))
        if len(rnd['accepts']) < need:
            return True
        # Decided. Tell everyone, and write it here.
        k, raw, sigs = rnd['k'], rnd['value'], dict(rnd['accepts'])
        self._place_vars()['_place_rounds'].pop(key, None)
        self._place_send(queues, ReputationProtocol.placed,
                         {'group': key, 'k': k, 'value': raw, 'sigs': sigs},
                         self._place_target(key))
        if self._apply_placement(chain, key, k, rnd['entries'], sigs,
                                 group if key else None):
            v = self._place_vars()
            v['_placers'][key] = str(self.identity.uuid).lower()
            # Our ballot still carries the next instance (see "The leader
            # skips the first phase" above) -- unless the group changed: a
            # promise given under the old roster is asked for again.
            if any(e.is_roster for e in rnd['entries']):
                v['_place_lead'].pop(key, None)
            else:
                v['_place_lead'][key] = (chain.next_index, rnd['ballot'])
        return True

    def handle_place_nack(self, queues, message):
        if message.function != ReputationProtocol.place_nack:
            return False
        got = self._place_payload(message)
        if got is None:
            return True
        payload, key, chain, _group = got
        v = self._place_vars()
        promised = parse_ballot(payload.get('promised'))
        if promised is not None:
            v['_place_seen_n'] = max(v['_place_seen_n'], promised[0])
        rnd = self._place_round_for(payload, key)
        # Only a member deciding the instance can refuse it: a node the
        # roster does not list yet -- one waiting to be added, still behind
        # -- would otherwise end every round that adds it.
        if rnd is None or self._place_voter(message, key, payload['k']) is None:
            return True
        v['_place_rounds'].pop(key, None)
        v['_place_lead'].pop(key, None)
        v['_place_backoff'][key] = time.monotonic() + random.uniform(*self.PLACE_BACKOFF)
        nxt = payload.get('next')
        if isinstance(nxt, int) and nxt > chain.next_index:
            try:
                self._request_update(queues, key=key)
            except Full:
                pass
        return True

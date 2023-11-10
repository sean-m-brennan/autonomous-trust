#!/usr/bin/env python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))
from autonomous_trust.core.identity import Identity
from autonomous_trust.core import from_yaml_string


def validate(directory, expected_groups=1, debug=False):
    seen_uuids = {}
    seen_encryptors = {}
    seen_signatures = {}
    seen_groups = {}
    grp_uuids = {}
    grp_encryptors = {}
    grp_nicknames = {}
    etc_count = 0
    identity_files = 0
    group_files = 0
    peer_files = 0
    missing_idents = []
    missing_groups = []
    missing_peers = []
    for root, dirs, files in os.walk(directory):
        if 'etc' in root:
            for d in dirs:
                if d == 'at':
                    if debug:
                        print(root, d)
                    etc_count += 1
                    missing_idents.append(os.path.dirname(root))
                    missing_groups.append(os.path.dirname(root))
                    missing_peers.append(os.path.dirname(root))
            for file in files:
                if file == 'identity.cfg.yaml':
                    if debug:
                        print(root, file)
                    missing_idents.remove(os.path.dirname(os.path.dirname(root)))
                    identity_files += 1
                    file = os.path.join(os.path.relpath(root, directory), file)
                    ident = Identity.from_file(file)
                    if ident.uuid in seen_uuids:
                        prev = seen_uuids[ident.uuid]
                        print('%s has UUID used in %s' % (file, prev))
                    else:
                        seen_uuids[ident.uuid] = file
                    if ident.encryptor.publish() in seen_encryptors:
                        prev = seen_encryptors[ident.encryptor.publish()]
                        print('%s has encryptor used in %s' % (file, prev))
                    else:
                        seen_encryptors[ident.encryptor.publish()] = file
                    if ident.signature.publish() in seen_signatures:
                        prev = seen_signatures[ident.signature.publish()]
                        print('%s has signature used in %s' % (file, prev))
                    else:
                        seen_signatures[ident.signature.publish()] = file
                if file == 'group.cfg.yaml':
                    if debug:
                        print(root, file)
                    missing_groups.remove(os.path.dirname(os.path.dirname(root)))
                    group_files += 1
                    file = os.path.join(os.path.relpath(root, directory), file)
                    with open(file, 'r') as cfg:
                        result = from_yaml_string(cfg.read())
                    if result is None:
                        print('Empty group for %s' % file)
                        continue
                    try:
                        grp, hist_dict = result
                        grp_hash = grp.uuid + grp.encryptor.publish().decode() + grp.nickname
                    except AttributeError:
                        print('Malformed config: %s' % file)
                        continue
                    if grp_hash not in seen_groups:
                        seen_groups[grp_hash] = []
                    seen_groups[grp_hash] += file
                    if grp.uuid not in grp_uuids:
                        grp_uuids[grp.uuid] = []
                    grp_uuids[grp.uuid] += file
                    if grp.encryptor.publish() not in grp_encryptors:
                        grp_encryptors[grp.encryptor.publish()] = []
                    grp_encryptors[grp.encryptor.publish()] += file
                    if grp.nickname not in grp_nicknames:
                        grp_nicknames[grp.nickname] = []
                    grp_nicknames[grp.nickname] += file
                if file == 'peers.cfg.yaml':
                    if debug:
                        print(root, file)
                    missing_peers.remove(os.path.dirname(os.path.dirname(root)))
                    peer_files += 1
    ident_diff = etc_count - identity_files
    if ident_diff:
        print('Missing %d identity configs: %s' % (ident_diff, ', '.join(missing_idents)))
    grp_diff = etc_count - group_files
    if grp_diff:
        print('Missing %d group configs: %s' % (grp_diff, ', '.join(missing_groups)))
    if len(seen_groups) > expected_groups:
        print('Too many groups: %d' % len(seen_groups))
        print('    Differing uuids: %d' % len(grp_uuids))
        print('    Differing encryptors: %d' % len(grp_encryptors))
        print('    Differing nicknames: %d' % len(grp_nicknames))
    peer_diff = etc_count - peer_files
    if peer_diff:
        print('Missing %d peer configs: %s' % (peer_diff, ', '.join(missing_peers)))


if __name__ == '__main__':
    direct = os.getcwd()
    if len(sys.argv) > 1:
        direct = sys.argv[1]
    validate(direct)

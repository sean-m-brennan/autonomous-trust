# AutonomousTrust First Contact

First contact, adding a specific person you already know, as a distribution
separate from the core (FEATURE_SPLIT_PLAN Phase 7):

| Module | What it is |
|---|---|
| `autonomous_trust.first_contact.contact`, `.store` | the `Contact` record and the address book (`contacts.cfg.json`) |
| `autonomous_trust.first_contact.invitation` | signed out-of-band invitations, safety numbers |
| `autonomous_trust.first_contact.first_contact` | the 1:1 handshake, the §10.3 tier cap, the trust seeds |
| `autonomous_trust.first_contact.directory`, `.directory_contact` | finding someone by handle |
| `autonomous_trust.first_contact.area_card`, `.area_contact` | finding people nearby at an area hub |
| `autonomous_trust.first_contact.device`, `.device_contact`, `.siblings`, `.sibling_sync`, `.sync` | one human's several devices |
| `autonomous_trust.first_contact.backup`, `.backup_contact` | the encrypted address-book backup |
| `autonomous_trust.first_contact.registry`, `.hub`, `.fc_net` | the directory registry and area hub a relay serves, and their clients |

The package-level names are the old `autonomous_trust.core.contacts` ones:
`from autonomous_trust.first_contact import Contacts, Invitation`.

The core names nothing here. It finds this package through the
`autonomous_trust.extensions` entry points when installed, or through
`autonomous_trust/first_contact/_at_extension.py` in a source tree (put
`src/autonomous-trust-first-contact` on `PYTHONPATH` beside
`src/autonomous-trust`), and reaches it only through the extension hooks:
identity's, negotiation's tier cap, reputation's trust seeds, the network
process's, and the relay's server ops. Rendezvous, the relay itself and the
signed reachability records, is still the core's.

Installing it changes nothing on its own. A node runs the handshake only when
`AT_FIRST_CONTACT` is set, and then its five plaintext verbs must be granted
by `unencrypted_verbs.cfg.json`.

The C twin is `libat_first_contact` (`src/c/extensions/first_contact/`); see
`doc/architecture/extensions.md`.

## Operator tools

Scripts in `tools/`, run with this distribution and the core on `PYTHONPATH`:

| Tool | What it does |
|---|---|
| `tools/device_cert.py` | issues and verifies a device's cert under the operator key |
| `tools/backup.py` | exports, inspects and imports an address-book backup, and restores the operator key |
| `tools/directory_issuer.py` | an issuer's keypair, and signing a handle attestation for the directory |

## Tests

```
./run-tests.sh
```

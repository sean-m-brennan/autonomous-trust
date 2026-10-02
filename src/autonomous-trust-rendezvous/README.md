# AutonomousTrust Rendezvous

Rendezvous, reaching a node across NAT, as a distribution separate from the
core (FEATURE_SPLIT_PLAN Phase 7b):

| Module | What it is |
|---|---|
| `autonomous_trust.rendezvous.relay` | the relay client and server, relay proofs, hints |
| `autonomous_trust.rendezvous.reach` | signed reachability records |
| `autonomous_trust.rendezvous.relay_seeds`, `.relay_rosters` | the signed seed list and community rosters |
| `autonomous_trust.rendezvous.rdv_net` | the network process's relay routes, failover and relay gate |
| `autonomous_trust.rendezvous.roster` | the roster app verbs and their `RosterEvent` |
| `autonomous_trust.rendezvous.rendezvous` | the extension, and the services that ride the relays |

The core names nothing here. It finds this package through the
`autonomous_trust.extensions` entry point when installed, or through
`autonomous_trust/rendezvous/_at_extension.py` in a source tree (put
`src/autonomous-trust-rendezvous` on `PYTHONPATH` beside
`src/autonomous-trust`), and reaches it only through the network hooks and the
identity handlers it registers. First contact
(`src/autonomous-trust-first-contact`) depends on it.

`AT_USE_RELAY` registers with relays, `AT_RELAY` serves as one, and
`AT_RELAY_SEED_FALLBACK` lets the pinned communities' rosters and then the
signed seed list stand in for `AT_USE_RELAY`. A node with any of them set but
without this package refuses to start.

The C twin is `libat_rendezvous` (`src/c/extensions/rendezvous/`); see
`doc/architecture/extensions.md`.

## Operator tools

Scripts in `tools/`, run with this distribution and the core on `PYTHONPATH`:

| Tool | What it does |
|---|---|
| `tools/relay_seeds.py` | the release signer's seed list (`keygen`, `sign`, `verify`) and the node's local additions (`local`, `show`) |
| `tools/relay_rosters.py` | a community's roster (`keygen`, `sign`, `verify`) and the node's pinned issuers (`pin`, `unpin`, `install`, `show`) |

## Tests

```
./run-tests.sh
```

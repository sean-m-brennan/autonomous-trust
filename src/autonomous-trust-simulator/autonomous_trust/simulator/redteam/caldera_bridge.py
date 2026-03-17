"""CLI bridge for CALDERA abilities to invoke AttackScenario.collect().

Invoked by sandcat agents inside AT containers:
    python -m autonomous_trust.simulator.redteam.caldera_bridge \
        --attack sybil --action collect \
        --config /tmp/caldera-config/attack-config.json

Reads attack constructor args from the config JSON file, instantiates the
corresponding AttackScenario, calls collect(), and prints JSON to stdout.
"""

import argparse
import inspect
import json
import sys

from autonomous_trust.simulator.redteam.sybil_attack import SybilAttack
from autonomous_trust.simulator.redteam.byzantine_node import ByzantineNodeAttack
from autonomous_trust.simulator.redteam.reputation_gaming import ReputationGamingAttack

ATTACK_MAP = {
    'sybil': SybilAttack,
    'byzantine': ByzantineNodeAttack,
    'reputation_gaming': ReputationGamingAttack,
}


def dispatch_collect(attack_name: str, config: dict) -> dict:
    """Instantiate scenario from config and call collect().

    Args:
        attack_name: Key into ATTACK_MAP.
        config: Constructor kwargs for the AttackScenario subclass.

    Returns:
        Dict with attack_specific metrics from collect().
    """
    cls = ATTACK_MAP[attack_name]
    sig = inspect.signature(cls.__init__)
    valid_keys = {p for p in sig.parameters if p != 'self'}
    kwargs = {k: v for k, v in config.items() if k in valid_keys}
    scenario = cls(**kwargs)
    return scenario.collect({})


def main():
    parser = argparse.ArgumentParser(
        description='CALDERA bridge: dispatch to AttackScenario.collect()')
    parser.add_argument('--attack', required=True,
                        help='Attack name: sybil, byzantine, reputation_gaming')
    parser.add_argument('--action', required=True, choices=['collect'],
                        help='Action to perform (only collect is supported)')
    parser.add_argument('--config', required=True,
                        help='Path to JSON config with scenario constructor args')
    args = parser.parse_args()

    try:
        with open(args.config) as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(json.dumps({'error': str(e)}), file=sys.stderr)
        sys.exit(1)

    try:
        result = dispatch_collect(args.attack, config)
    except KeyError:
        print(json.dumps({'error': f'Unknown attack: {args.attack}'}),
              file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

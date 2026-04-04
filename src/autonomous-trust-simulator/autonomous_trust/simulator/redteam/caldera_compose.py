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
"""Patch docker-compose YAML to add CALDERA server, sandcat agents, and attack pre-config.

Called by test-simulation-scenarios.sh when --caldera flag is set.
Takes the YAML from generate_appalachian_compose(), adds CALDERA infrastructure,
and returns the modified YAML string.
"""

import json
import os
import stat
import yaml

CALDERA_IMAGE = 'ghcr.io/mitre/caldera:5.2.0'
CALDERA_IP = '10.27.3.2'
CALDERA_PORT = 8888
CALDERA_URL = f'http://{CALDERA_IP}:{CALDERA_PORT}'
SYBIL_BASE_IP_OFFSET = 30

SCENARIO_TO_CALDERA = {
    'sybil_attack': 'sybil',
    'byzantine_node': 'byzantine',
    'reputation_gaming': 'reputation_gaming',
}
CALDERA_ATTACK_NAMES = set(SCENARIO_TO_CALDERA.values())

_REDTEAM_DIR = os.path.dirname(os.path.abspath(__file__))


def patch_caldera(compose_yaml: str, attacks: list[str],
                  attack_config: dict, work_dir: str) -> str:
    data = yaml.safe_load(compose_yaml)
    services = data.get('services', {})

    _add_caldera_server(services, work_dir)
    _add_sandcat_to_services(services, work_dir)
    _write_attack_config(attack_config, work_dir)

    if 'sybil' in attacks:
        _add_sybil_services(services, attack_config)
    if 'byzantine' in attacks:
        _add_byzantine_env(services, attack_config)
    if 'reputation_gaming' in attacks:
        _add_gaming_env(services, attack_config)

    data['services'] = services
    return yaml.dump(data, default_flow_style=False, sort_keys=False)


def _add_caldera_server(services: dict, work_dir: str) -> None:
    api_key = os.environ.get('CALDERA_API_KEY', 'ADMIN123')

    caldera_config_dir = os.path.join(work_dir, 'caldera-conf')
    os.makedirs(caldera_config_dir, exist_ok=True)
    local_yml = os.path.join(caldera_config_dir, 'local.yml')
    with open(local_yml, 'w') as f:
        yaml.dump({
            'api_key_red': api_key,
            'api_key_blue': api_key,
            'host': CALDERA_IP,
            'port': CALDERA_PORT,
            'plugins': ['sandcat', 'stockpile'],
            'app.contact.http': CALDERA_URL,
            'app.contact.websocket': f'{CALDERA_IP}:7012',
            'crypt_salt': 'autonomous_trust_redteam',
            'encryption_key': api_key,
        }, f)

    profiles_dir = os.path.join(_REDTEAM_DIR, 'adversary_profiles')
    abilities_dir = os.path.join(_REDTEAM_DIR, 'caldera_abilities')

    services['caldera-server'] = {
        'image': CALDERA_IMAGE,
        'container_name': 'caldera-server',
        'hostname': 'caldera-server',
        'environment': {
            'CALDERA_URL': CALDERA_URL,
        },
        'volumes': [
            f'{caldera_config_dir}/local.yml:/usr/src/app/conf/local.yml:ro',
            f'{profiles_dir}:/usr/src/app/data/adversaries/custom:ro',
            f'{abilities_dir}:/usr/src/app/data/abilities/custom:ro',
        ],
        'networks': {
            'at-net': {'ipv4_address': CALDERA_IP},
        },
    }


def _add_sandcat_to_services(services: dict, work_dir: str) -> None:
    wrapper_path = _write_wrapper_script(work_dir)
    config_dir = os.path.join(work_dir, 'caldera-config')
    os.makedirs(config_dir, exist_ok=True)

    for name, svc in list(services.items()):
        if name == 'caldera-server':
            continue
        svc['image'] = 'autonomous-trust-full-devel'
        svc['entrypoint'] = ['/usr/local/bin/caldera_sandcat_wrapper.sh']
        volumes = svc.get('volumes', [])
        volumes.append(f'{wrapper_path}:/usr/local/bin/caldera_sandcat_wrapper.sh:ro')
        volumes.append(f'{config_dir}:/tmp/caldera-config:ro')
        svc['volumes'] = volumes
        depends = svc.get('depends_on', [])
        depends.append('caldera-server')
        svc['depends_on'] = depends


def _write_wrapper_script(work_dir: str) -> str:
    script_path = os.path.join(work_dir, 'caldera_sandcat_wrapper.sh')
    content = f"""#!/bin/bash
# Sandcat wrapper: download and start sandcat, then delegate to AT entrypoint.
# The sandcat download runs in the background so it never delays AT startup.
CALDERA_URL="{CALDERA_URL}"
SERVICE_NAME="${{HOSTNAME}}"
SANDCAT_PATH="/tmp/sandcat"

echo "[$SERVICE_NAME] Sandcat wrapper starting ..."

# Background: download sandcat and start agent once ready.
_download_sandcat() {{
    for i in $(seq 1 6); do
        if command -v curl >/dev/null 2>&1; then
            curl -sf --connect-timeout 5 --max-time 10 \\
                -o "$SANDCAT_PATH" \\
                "$CALDERA_URL/file/download" \\
                -d "platform=linux&file=sandcat" && break
        elif command -v wget >/dev/null 2>&1; then
            wget -q --timeout=10 -O "$SANDCAT_PATH" \\
                "$CALDERA_URL/file/download?platform=linux&file=sandcat" && break
        else
            timeout 10 python -c "import urllib.request; urllib.request.urlretrieve('$CALDERA_URL/file/download?platform=linux&file=sandcat', '$SANDCAT_PATH')" && break
        fi
        sleep 5
    done
    if [ -f "$SANDCAT_PATH" ]; then
        chmod +x "$SANDCAT_PATH"
        echo "[$SERVICE_NAME] Starting sandcat agent ..."
        "$SANDCAT_PATH" -server "$CALDERA_URL" -group "$SERVICE_NAME"
    else
        echo "[$SERVICE_NAME] WARNING: Sandcat download failed — no agent."
    fi
}}
_download_sandcat &

# Delegate to original entrypoint immediately (handles conda, PYTHONPATH, etc.)
echo "[$SERVICE_NAME] Handing off to AT entrypoint ..."
exec /bin/entrypoint.sh "$@"
"""
    with open(script_path, 'w') as f:
        f.write(content)
    os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
             stat.S_IROTH | stat.S_IXOTH)
    return script_path


def _write_attack_config(config: dict, work_dir: str) -> None:
    config_dir = os.path.join(work_dir, 'caldera-config')
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, 'attack-config.json'), 'w') as f:
        json.dump(config, f, indent=2)


def _add_sybil_services(services: dict, config: dict) -> None:
    num = config.get('num_sybil_nodes', 3)
    offset = config.get('base_ip_offset', SYBIL_BASE_IP_OFFSET)
    for i in range(num):
        name = f'sybil-{i + 1}'
        ip = f'10.27.3.{offset + i}'
        services[name] = {
            'image': 'autonomous-trust-full-devel',
            'container_name': name,
            'hostname': name,
            'cap_add': ['NET_ADMIN'],
            'environment': {
                'ROUTER': '10.27.3.1',
                'AUTONOMOUS_TRUST_BACKEND': 'python',
                'SYBIL_NODE': 'true',
                'STARTUP_DELAY': str(i * 2),
            },
            'networks': {
                'at-net': {'ipv4_address': ip},
            },
            'depends_on': ['caldera-server'],
        }


def _add_byzantine_env(services: dict, config: dict) -> None:
    for peer_id in config.get('byzantine_peer_ids', []):
        if peer_id in services:
            env = services[peer_id].get('environment', {})
            env['BYZANTINE_MODE'] = 'true'
            services[peer_id]['environment'] = env


def _add_gaming_env(services: dict, config: dict) -> None:
    defection_time = config.get('defection_time_s', 60.0)
    for peer_id in config.get('gaming_peer_ids', []):
        if peer_id in services:
            env = services[peer_id].get('environment', {})
            env['GAMING_MODE'] = 'true'
            env['DEFECTION_TIME_S'] = str(defection_time)
            services[peer_id]['environment'] = env

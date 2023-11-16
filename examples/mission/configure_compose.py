#!/usr/bin/env python

import os
import sys
from typing import TextIO

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(base_dir)
import build_tools as tools  # noqa


class DockerCompose(object):
    num_participants = 9

    compose_cfg_version = 3
    namespace = tools.config.swarm_namespace
    network_name = tools.config.network_name
    router = tools.docker.network.get_default_route_info()[0]
    registry_host = tools.config.registry_host
    registry_port = tools.config.registry_port

    command = 'ls /app/autonomous_trust/core'

    def __init__(self, user: str = None, path: str = None, split: bool = False, extern_net: bool = True,
                 swarm: bool = False, host: bool = False, interactive: bool = False):
        self.image = '%s:%d/autonomous-trust-full-devel:latest' % (self.registry_host, self.registry_port)
        self.uid = user
        if user is None:
            self.uid = '%d:%d' % (os.getuid(), os.getgid())
        if path is None:
            path = os.path.abspath(os.path.dirname(__file__))
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        base = os.path.abspath(os.path.join(path, '..', '..'))
        user_path = os.path.expanduser('~')
        self.path = os.path.normpath(path.replace(user_path, '~/'))
        self.base = os.path.normpath(base.replace(user_path, '~/'))
        self.split = split
        self.extern_net = extern_net
        self.with_host = host
        self.interactive = interactive
        self.depend = False

        self.compose_ver = self.compose_cfg_version
        if swarm and self.compose_ver < 3:
            self.compose_ver = 3

    def participant(self, num: int, cfg: TextIO):
        num_str = str(num).zfill(3)
        interact_deps = ''
        if self.interactive:
            interact_deps = '    stdin_open: true\n    tty: true\n    command: bash -c "%s"\n' % self.command
        elif self.depend:
            interact_deps = '    depends_on:\n      - simulator\n'
        cfg.write("  participant%d:\n" % num +
                  "    image: %s\n" % self.image +
                  "    volumes:\n" +
                  "      - %s/lib/autonomous_trust:/app/autonomous_trust\n" % self.base +
                  "      - %s/participant/participant.py:/app/participant.py\n" % self.path +
                  "      - %s/participant/%s:/app/%s\n" % (self.path, num_str, num_str) +
                  "      - %s/participant/var:/app/var\n" % self.path +
                  "    user: %s\n" % self.uid +
                  "    networks:\n" +
                  "      - %s\n" % self.network_name +
                  "    cap_add:\n" +
                  "      - NET_ADMIN\n" +
                  "    environment:\n" +
                  "      AUTONOMOUS_TRUST_EXE: \"participant.py %d\"\n" % num +
                  "      ROUTER: \"%s\"\n" % self.router +
                  "    deploy:\n" +
                  "      replicas: 1\n" +
                  interact_deps +
                  "\n")

    def coordinator(self, cfg: TextIO):
        # if using macvlan, cannot be on the same host as the browser
        interact_deps = ''
        if self.interactive:
            interact_deps = '    stdin_open: true\n    tty: true\n    command: bash -c "%s"\n' % self.command
        elif self.depend:
            interact_deps = '    depends_on:\n      - simulator\n'
        cfg.write("  coordinator:\n" +
                  "    image: %s\n" % self.image +
                  "    volumes:\n" +
                  "      - %s/lib/autonomous_trust:/app/autonomous_trust\n" % self.base +
                  "      - %s/coordinator/coordinator.py:/app/coordinator.py\n" % self.path +
                  "      - %s/coordinator/etc:/app/etc\n" % self.path +
                  "      - %s/coordinator/var:/app/var\n" % self.path +
                  "    user: %s\n" % self.uid +
                  # "    ports:\n" +
                  # "      - \"8050:8050\"\n" +
                  "    networks:\n" +
                  "      - %s\n" % self.network_name +
                  "    cap_add:\n" +
                  "      - NET_ADMIN\n" +
                  "    environment:\n" +
                  "      AUTONOMOUS_TRUST_EXE: \"coordinator.py\"\n" +
                  "      ROUTER: \"%s\"\n" % self.router +
                  "    deploy:\n" +
                  "      replicas: 1\n" +
                  "      placement:\n" +
                  "        constraints:\n" +
                  "          - 'node.role == worker'\n" +
                  interact_deps +
                  "\n")

    def simulator(self, cfg: TextIO):
        log_level = 'info'
        log_file = 'simulator.log'
        options = '--log %s --log-level %s --resolve-short-name' % (log_file, log_level)
        interact = ''
        if self.interactive:
            interact = '    stdin_open: true\n    tty: true\n    command: bash -c "%s"\n' % self.command
        cfg.write("  simulator:\n" +
                  "    image: %s\n" % self.image +
                  "    volumes:\n" +
                  "      - %s/lib/autonomous_trust:/app/autonomous_trust\n" % self.base +
                  "      - %s/simulator/scenario.yaml:/app/scenario.yaml\n" % self.path +
                  "      - %s/simulator/etc:/app/etc\n" % self.path +
                  "    user: %s\n" % self.uid +
                  "    networks:\n" +
                  "      - %s\n" % self.network_name +
                  "    cap_add:\n" +
                  "      - NET_ADMIN\n" +
                  "    environment:\n" +
                  "      AUTONOMOUS_TRUST_EXE: \"-m autonomous_trust.simulator %s scenario.yaml\"\n" % options +
                  "      AUTONOMOUS_TRUST_ROOT: \"/app\"\n" +
                  "      ROUTER: \"%s\"\n" % self.router +
                  "    deploy:\n" +
                  "      replicas: 1\n" +
                  # "      placement:\n" +
                  # "        constraints:\n" +
                  # "          - 'node.role == worker'\n" +
                  interact +
                  "\n")

    def single(self, cfg: TextIO):
        self.depend = True
        self.simulator(cfg)
        self.coordinator(cfg)
        for idx in range(1, self.num_participants + 1):
            self.participant(idx, cfg)
        self.network(cfg)

    def network(self, cfg: TextIO):
        if self.extern_net:
            cfg.write("networks:\n  %s:\n    external: true\n\n" % self.network_name)
        else:
            cfg.write(tools.docker.network.compose_config(self.compose_ver, self.with_host))

    @staticmethod
    def get_ip_address():
        return tools.docker.network.get_default_route_info()[1]

    def create(self):
        if self.split:  # for debugging, using `docker compose up`
            self._create_cfg('simulator')
            self._create_cfg('coordinator')
            for i in range(1, 10):
                self._create_cfg('participant%d' % i)
        else:  # default, for use with `docker stack deploy autonomous_trust`
            self._create_cfg('single')

    def _create_cfg(self, which: str):
        filename = '%s_docker-compose.yaml' % which
        if which == 'simulator':
            creator = self.simulator
        elif which == 'coordinator':
            creator = self.coordinator
        elif which.startswith('participant'):
            number = which[11:]
            if number == '':
                number = 1
            else:
                number = int(number)
            creator = lambda *args: self.participant(number, *args)  # noqa
        elif which == 'single':
            creator = self.single
            filename = 'docker-compose.yaml'
        else:
            print('Invalid type: %s' % which)
            return

        print('Create docker compose config: %s' % filename)
        address = self.get_ip_address()

        with open(filename, 'w') as cfg:
            cfg.write('# Prerequisites:\n' +
                      '#\ton the manager: run `docker swarm init --advertise-addr %s`\n' % address +
                      '#\ton workers: run `docker swarm join ...` with the token and endpoint of the manager\n\n')
            cfg.write('# On the manager node, run with `docker stack deploy --compose-file %s %s`\n\n' %
                      (filename, self.namespace))
            cfg.write("version: '%d'\nservices:\n" % self.compose_ver)
            creator(cfg)
            if which != 'single':
                self.network(cfg)


if __name__ == '__main__':
    mission_path = os.path.dirname(__file__)  # also assumes filesystem uniformity across machines
    DockerCompose(path=mission_path, split='--split' in sys.argv, swarm='--swarm' in sys.argv,
                  host='--host' in sys.argv, interactive='--debug' in sys.argv).create()

#!/usr/bin/env python
import os
import socket
from typing import TextIO


NAMESPACE = 'autonomous_trust'


def participant(num: int, cfg: TextIO, image: str, uid: str, path: str):
    num_str = str(num).zfill(3)
    cfg.write("  participant%d:\n" % num +
              "    image: %s\n" % image +
              "    volumes:\n" +
              "      - %s/participant/participant.py:/app/participant.py\n" % path +
              "      - %s/participant/%s:/app/%s\n" % (path, num_str, num_str) +
              "      - %s/participant/var:/app/var\n" % path +
              "    user: %s\n" % uid +
              "    environment:\n" +
              "      AUTONOMOUS_TRUST_EXE: \"participant.py %d\"\n" % num +
              "    depends_on:\n" +
              "      - simulator\n\n")


def coordinator(cfg: TextIO, image: str, uid: str, path: str):
    cfg.write("  coordinator:\n" +
              "    image: %s\n" % image +
              "    volumes:\n" +
              "      - %s/coordinator/coordinator.py:/app/coordinator.py\n" % path +
              "      - %s/coordinator/etc:/app/etc\n" % path +
              "    user: %s\n" % uid +
              "    environment:\n" +
              "      AUTONOMOUS_TRUST_EXE: \"coordinator.py\"\n" +
              "    depends_on:\n" +
              "      - simulator\n\n")  # FIXME expose port 8050


def simulator(cfg: TextIO, image: str, uid: str, path: str):
    cfg.write("  simulator:\n" +
              "    image: %s\n" % image +
              "    volumes:\n" +
              "      - %s/simulator/scenario.cfg:/app/scenario.yaml\n" % path +
              "    user: %s\n" % uid +
              "    environment:\n" +
              "      AUTONOMOUS_TRUST_EXE: \"-m autonomous_trust.simulator scenario.yaml\"\n\n")


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(0)
        s.connect(('10.254.254.254', 1))
        addr = s.getsockname()[0]
    finally:
        s.close()
    return addr


def create_cfg(which: str, user: str = None, path: str = None):
    image = 'autonomous-trust-full-devel:latest'
    if user is None:
        user = os.environ.get('USER')
    if path is None:
        path = os.path.abspath(os.path.dirname(__file__))
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    user_path = os.path.expanduser('~')
    path = os.path.normpath(path.replace(user_path, '~/'))

    if which == 'simulator':
        creator = simulator
    elif which == 'coordinator':
        creator = coordinator
    elif which.startswith('participant'):
        number = which[11:]
        if number == '':
            number = 1
        else:
            number = int(number)
        creator = lambda *args: participant(number, *args)  # noqa
    else:
        print('Invalid type: %s' % which)
        return

    filename = '%s_docker-compose.yaml' % which
    print('Create docker compose config: %s' % filename)
    address = get_ip_address()

    with open(filename, 'w') as cfg:
        cfg.write('# Prerequisites:\n' +
                  '#\ton the manager: run `docker swarm init --advertise-addr %s`\n' % address +
                  '#\ton workers: run `docker swarm join ...` with the token and endpoint of the manager\n\n')
        cfg.write('# On the manager node, run with `docker stack deploy --compose-file %s %s`\n\n' % (filename, NAMESPACE))
        cfg.write("version: '3'\nservices:\n")
        creator(cfg, image, user, path)


if __name__ == '__main__':
    user_tpl = '%d:%d' % (os.getuid(), os.getgid())  # assumes uid uniformity across machines
    mission_path = os.path.dirname(__file__)  # also assumes filesystem uniformity across machines
    create_cfg('simulator', user_tpl, mission_path)
    create_cfg('coordinator', user_tpl, mission_path)
    for i in range(1, 10):
        create_cfg('participant%d' % i, user_tpl, mission_path)

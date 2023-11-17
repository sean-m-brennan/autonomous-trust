#!/usr/bin/env python

import argparse
import os
import subprocess
import sys
import traceback

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'lib'))

from autonomous_trust.core import Configuration  # noqa
import build_tools as tools  # noqa


def run(command_line: list[str]):
    try:
        subprocess.check_call(command_line)
    except subprocess.CalledProcessError:
        pass


def get_worker_device(worker):
    routes = subprocess.check_output(['ssh', worker, 'ip -o -4 route show']).decode().split('\n')
    return routes[0].split()[4]


class ClusterConfig(Configuration):
    def __init__(self, manager: str, workers: list[str] = None):
        my_ip = tools.docker.network.get_default_route_info()[1]
        self.manager = manager
        if self.manager != my_ip:
            raise RuntimeError('Cluster must be run from the manager (%s); attempting to run from %s' %
                               (self.manager, my_ip))
        self.workers = workers
        if workers is None:
            self.workers = []

    def startup(self, without_swarm: bool = False, extern_net: bool = True):
        with_swarm = not without_swarm
        if with_swarm:
            cfg_name = tools.config.network_cfg_name
            cmd = tools.docker.network.create_network(name=cfg_name, config_only=True, force=True)
            for worker in self.workers:
                dev = get_worker_device(worker)
                remote_cmd = []
                for field in list(cmd):
                    if field.startswith('parent='):
                        field = 'parent=' + dev
                    remote_cmd.append(field)
                print('%s -> %s' % (worker, ' '.join(remote_cmd)))
                run(['ssh', worker, ' '.join(remote_cmd)])

            try:
                result = subprocess.check_output(['docker', 'swarm', 'join-token', '-q', 'worker'],
                                                 stderr=subprocess.DEVNULL)
                print('Docker Swarm worker token: %s' % result.decode().strip())
            except subprocess.CalledProcessError:
                result = subprocess.check_output(['docker', 'swarm', 'init', '--advertise-addr', self.manager])
                for line in result.decode().split('\n'):
                    if '--token' in line:
                        token = line.split()[4]
                        addr = line.split()[5]
                        for worker in self.workers:
                            print(worker)
                            run(['ssh', worker, 'docker swarm join --token %s %s' % (token, addr)])
                        break

            tools.docker.network.create_network(swarm_scope=with_swarm, config_from=cfg_name, force=True, debug=True)
        elif extern_net:
            tools.docker.network.create_network(swarm_scope=with_swarm, force=True)

    def shutdown(self):
        result = subprocess.check_output(['docker', 'stack', 'services', tools.config.swarm_namespace],
                                         stderr=subprocess.DEVNULL)
        for line in result.decode().strip().split('\n')[1:]:
            service = line.split()[1]
            run(['docker', 'service', 'rm', service])
        for worker in self.workers:
            run(['ssh', worker, 'docker', 'swarm', 'leave', '--force'])
            run(['ssh', worker, 'docker', 'network', 'rm', '--force', tools.config.network_cfg_name])
            run(['ssh', worker, 'docker', 'network', 'prune', '-f'])
        run(['docker', 'network', 'rm', '--force', tools.config.network_name])
        run(['docker', 'swarm', 'leave', '--force'])
        run(['docker', 'network', 'rm', '--force', tools.config.network_cfg_name])
        run(['docker', 'network', 'prune', '-f'])


def setup_registry(cluster: ClusterConfig, without_swarm: bool = False):
    certs_dir = os.path.join(tools.config.REGISTRY_DISK, 'certs')
    reg_key = os.path.join(certs_dir, 'registry.key')
    reg_crt = os.path.join(certs_dir, 'registry.crt')
    if not os.path.exists(reg_key) or not os.path.exists(reg_crt):
        subprocess.check_call(['openssl', 'req', 'rsa:4096', '-nodes', '-sha256', '-keyout', reg_key, '-x509',
                               '-days', '365', '-out', 'reg_crt',
                               '-subj', '"/C=US/ST=AL/L=Huntsville/O=TekFive Inc/CN=%s"' % tools.config.registry_host,
                               '-addext', '"subjectAltName = DNS:%s"' % tools.config.registry_host])

    docker_certs_dir = '/etc/docker/certs.d/%s:%s' % (tools.config.registry_host, tools.config.registry_port)
    cert = os.path.join(docker_certs_dir, 'ca.crt')
    if not os.path.exists(cert):
        subprocess.check_call(['sudo', 'mkdir', '-p', docker_certs_dir])
        subprocess.check_call(['sudo', 'cp', reg_crt, cert])
    with open('/etc/hosts', 'r') as hosts:
        lines = hosts.read()
    if tools.config.registry_host not in lines:
        subprocess.check_call(['sudo', 'sh', '-c', '"echo \"%s %s\" >> /etc/hosts"' %
                               (cluster.manager, tools.config.registry_host)])
        for worker in cluster.workers:
            run(['ssh', worker, '-c', '"echo \"%s %s\" >> /etc/hosts"' %
                 (worker, tools.config.registry_host)])

    registry_compose_file = os.path.abspath(os.path.join(base_dir, 'src', 'docker-registry.yaml'))
    if without_swarm:
        result = subprocess.check_output(['docker', 'ps'])
        need_registry = True
        for line in result.decode().strip().split('\n'):
            if line != '' and 'registry' in line.split()[1]:
                need_registry = False
        if need_registry:
            subprocess.check_call(['docker', 'compose', '-f', registry_compose_file, 'up', '-d'])
    else:
        result = subprocess.check_output(['docker', 'stack', 'services', tools.config.swarm_namespace],
                                         stderr=subprocess.DEVNULL)
        need_registry = True
        for line in result.decode().strip().split('\n'):
            if line != '' and 'registry' in line.split()[1]:
                need_registry = False
        if need_registry:
            subprocess.check_call(['docker', 'stack', 'deploy',
                                   '--compose-file', registry_compose_file, tools.config.swarm_namespace],
                                  env={'DOCKER_ROOT': tools.config.REGISTRY_DISK})


def run_example(wrk_dir: str, cluster: ClusterConfig, visualize: bool,
                compose_file: str = None, without_swarm: bool = False):
    if visualize and not without_swarm:
        subprocess.check_call(['docker', 'service', 'create', '--name=swarm-viz',
                               '--publish=8888:8080', '--constraint=node.role==manager',
                               '--mount=type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                               'dockersamples/visualizer'])

    setup_registry(cluster, without_swarm)

    if compose_file is None:
        compose_file = os.path.join(wrk_dir, 'docker-compose.yaml')
    if without_swarm:
        subprocess.check_call(['docker', 'compose', '-f', compose_file, 'up'])
    else:
        subprocess.check_call(['docker', 'stack', 'deploy', '--compose-file', compose_file,
                               tools.config.swarm_namespace])


if __name__ == '__main__':
    cwd = os.getcwd()
    lib_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'lib'))
    os.chdir(lib_dir)
    os.system('./update.sh')  # FIXME remove
    os.chdir(cwd)

    working_dir = os.path.abspath(os.path.dirname(__file__))
    examples = [f.name for f in os.scandir(working_dir) if f.is_dir()]

    parser = argparse.ArgumentParser()
    parser.add_argument('example', help='Example to run')
    parser.add_argument('--viz', action='store_true', help='also start swarm status visualization')
    parser.add_argument('--stop', action='store_true', help='stop a running example')
    parser.add_argument('-f', '--compose-file', type=str, help='docker-compose file to run')
    parser.add_argument('--without-swarm', action='store_true', help='start without swarm for debugging')
    parser.add_argument('--clean', action='store_true', help='delete logs')
    parser.add_argument('--pristine', action='store_true', help='delete network memory')
    args = parser.parse_args()

    if args.example not in examples:
        print('%s is not an example: %s' % (args.example, examples))
        sys.exit(1)

    working_dir = os.path.join(working_dir, args.example)
    cluster_cfg_file = os.path.join(working_dir, 'cluster.cfg.yaml')
    if not os.path.exists(cluster_cfg_file):
        print('Required cluster config file (%s) missing for the %s example' % (cluster_cfg_file, args.example))
        sys.exit(1)
    cluster_cfg = None
    try:
        cluster_cfg = Configuration.from_file(cluster_cfg_file)
    except RuntimeError:
        traceback.print_exc()
    if args.stop:
        try:
            results = subprocess.check_output(['docker', 'service', 'ls'])
            if 'swarm-viz' in results.decode():
                run(['docker', 'service', 'rm', 'swarm-viz'])
            run(['docker', 'service', 'rm', tools.config.swarm_namespace + '_registry'])
            if not args.without_swarm and cluster_cfg is not None:
                cluster_cfg.shutdown()
        except subprocess.CalledProcessError:
            pass
        delete_files = ['network.cfg.yaml']
        if args.clean or args.pristine:
            delete_files += ['"coordinator.log*"', '"participant???.log*"', 'simulator.log']
        if args.pristine:
            delete_files += ['group.cfg.yaml', 'peers.cfg.yaml', 'peer-capabilities.cfg.yaml', 'reputation.cfg.yaml']
        for cfg_name in delete_files:
            cfg_files = subprocess.getoutput('find %s -name %s' % (working_dir, cfg_name)).strip().split('\n')
            for cfg in cfg_files:
                if cfg != '':
                    os.remove(cfg)
    else:
        cluster_cfg.startup(args.without_swarm)
        run_example(working_dir, cluster_cfg, args.viz, args.compose_file, args.without_swarm)

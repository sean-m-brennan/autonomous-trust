import os
import docker
import autonomous_trust
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_container_is_ready, wait_for_logs

network_name = 'at-net'
network = '172.27.3.0'
mask = 24
host_dir = os.path.abspath(os.path.join(os.path.dirname(autonomous_trust.__file__), '..'))


def docker_init():
    client = docker.from_env()
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        print('Network $s not found. Must be created: run tools/network_init.sh')
    # FIXME builds differently (i.e. broken) than bash-scripted build
    #client.images.build(tag=image, path=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), nocache=False)


class AutonomousTrustContainer(DockerContainer):
    def __init__(self, image='autonomous-trust', **kwargs) -> None:
        super().__init__(image=image + ':latest', **kwargs)
        args = '--test'
        if 'tests' in kwargs:
            args = args + ' ' + kwargs['tests']
        self.with_env('AUTONOMOUS_TRUST_ARGS', args)
        self.with_kwargs(remove=True, network=network_name)
        self.ip_address = None

    @wait_container_is_ready(TimeoutError)
    def readiness_probe(self) -> None:
        wait_for_logs(self, lambda x: 'AutonomousTrust' in x)
        out, err = self.get_logs()
        for line in out.decode().split('\n'):
            if 'Bound peer recv to' in line:
                self.ip_address = line.split()[-1].split(':')[0]
                break
        #with open(os.path.join(host_dir, 'docker_ips'), 'a') as ip:
        #    ip.write(self.ip_address + '\n')

    def start(self) -> "AutonomousTrustContainer":
        super().start()
        self.readiness_probe()
        return self


class AutonomousTrustTestContainer(AutonomousTrustContainer):
    def __init__(self, **kwargs) -> None:
        super().__init__(image='autonomous-trust-test' + ':latest', **kwargs)
        args = '--test'
        if 'tests' in kwargs:
            args = args + ' ' + kwargs['tests']
        self.with_env('AUTONOMOUS_TRUST_TEST_ARGS', args)
        self.volumes[host_dir] = '/app'

    @wait_container_is_ready(TimeoutError)
    def readiness_probe(self) -> None:
        wait_for_logs(self, lambda x: 'AutonomousTrust' in x)  # FIXME

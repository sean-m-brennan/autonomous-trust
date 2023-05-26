import os
import time
import docker
from autonomous_trust.core.system import comm_port
from autonomous_trust.core.network.ping import ping
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_container_is_ready, wait_for_logs

network_name = 'at-net'
image = 'autonomous-trust'
network = '172.27.3.0'
mask = 24


def docker_init():
    client = docker.from_env()
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        print('Network $s not found. Must be created: run tools/network_init.sh')
    # FIXME builds differently (i.e. broken) than bash-scripted build
    #client.images.build(tag=image, path=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), nocache=False)


class AutonomousTrustContainer(DockerContainer):
    def __init__(self, **kwargs) -> None:
        super().__init__(image=image + ':latest', **kwargs)
        self.port = comm_port
        args = '--test'
        if 'tests' in kwargs:
            args = args + ' ' + kwargs['tests']
        self.with_env('AUTONOMOUS_TRUST_TEST_ARGS', args)
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
        time.sleep(5)
        #print(self.get_logs()[0].decode())
        stats = ping(self.ip_address)  # FIXME fails - blocked by docker?
        print(stats)

    def start(self) -> "AutonomousTrustContainer":
        super().start()
        self.readiness_probe()
        return self

import logging
import multiprocessing
import os
import sys

from autonomous_trust.core import Configuration, ProcessTracker, Process
from autonomous_trust.core.automate import ConfigMap
from autonomous_trust.core.config.discover import load_configs
from autonomous_trust.core.queue_pool import QueuePool
from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
from autonomous_trust.services.data.client import DataRcvr
from autonomous_trust.services.network_statistics import NetStatsSource
from autonomous_trust.services.video import VideoSource
from autonomous_trust.simulator.data_server import DataSimSource
from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource
from autonomous_trust.simulator.video.client import VideoSimRcvr
from .dash_components.map_display import MapDisplay
from .simulator import Simulator
from . import default_steps, default_port

if __name__ == '__main__':
    host: str = '127.0.0.1'
    port: int = 8050
    sim_port = default_port
    log_level = logging.DEBUG
    steps = default_steps
    config = sys.argv[1]

    coord_cfg = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             '..', '..', 'examples', 'mission', 'coordinator'))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = coord_cfg
    ctx = multiprocessing.get_context('forkserver')
    manager = ctx.Manager()
    with multiprocessing.Pool(5) as pool:
        # pool.apply_async(target=Simulator(config, max_time_steps=steps, log_level=log_level).run, args=(sim_port,))

        queue_pool = QueuePool(manager.Queue)
        cohort = Cohort(queue_pool, log_level=log_level)
        subsystems = ProcessTracker()
        configurations: ConfigMap = load_configs()
        log_queue = manager.Queue()
        dependencies = None

        configurations[Process.key].append(SimMetadataSource(configurations, subsystems, log_queue, dependencies))
        configurations[Process.key].append(NetStatsSource(configurations, subsystems, log_queue, dependencies))
        #configurations[Process.key].append(VideoSource(configurations, subsystems, log_queue, dependencies))
        configurations[Process.key].append(DataSimSource(configurations, subsystems, log_queue, dependencies))

        configurations[Process.key].append(CohortTracker(configurations, subsystems, log_queue, dependencies, cohort=cohort))
        configurations[Process.key].append(VideoSimRcvr(configurations, subsystems, log_queue, dependencies, cohort=cohort))
        configurations[Process.key].append(DataRcvr(configurations, subsystems, log_queue, dependencies, cohort=cohort))
        procs: list[Process] = configurations[Process.key]
        queues = dict(zip(list(map(lambda x: x.name, procs)), [manager.Queue() for _ in range(len(procs))]))
        signals: dict[str, manager.Queue] = {}

        for proc in configurations[Process.key]:
            pool.apply_async(proc.process, args=(queues, signals))

        viz = MapDisplay(cohort, force_local=True)
        #vthread = threading.Thread(target=MapDisplay(cohort).run,  # FIXME SimCohort instead??
        #                           kwargs={'logger': cohort.logger,
        #                                   'debug': cohort.log_level == logging.DEBUG,
        #                                   'verbose': False})
        viz.run(host, port, debug=True)

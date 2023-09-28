from autonomous_trust.services.peer.metadata import MetadataSource


class SimMetadataSource(MetadataSource):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        peer_kind = ''  # FIXME from my own config
        position_source = None  # FIXME from SimClient - needs interface with position acquire()
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies,
                         peer_kind=peer_kind, position_source=position_source)

from .command_parser import CommandParser, Command, Function, Argument
from .commands import tag, test
from . import devel, docker, unikernel

prog = 'trust'
version = '0.1.1'

default_num_test_nodes = 4
default_num_simulate_nodes = 20
default_num_emulate_nodes = 2
default_num_actuate_nodes = 2


class Cmds(object):
    devel = 'devel'
    network = 'network'
    tag = 'tag'
    docker = 'docker'
    unikernel = 'unikernel'
    test = 'test'
    simulate = 'simulate'
    emulate = 'emulate'
    actuate = 'actuate'


def main(commands, args):
    if args.version:
        print('%s version %s' % (prog, version))
        print('God is great')
        return
    for name, cmd in commands.items():
        if name == Cmds.devel:
            if cmd.function == 'init':
                devel.init()
        elif name == Cmds.network:
            pass  # FIXME
        elif name == Cmds.tag:
            tag.git_tag(cmd.level)
        elif name == Cmds.docker:
            if cmd.function is None:
                docker.build.build(cmd.force, cmd.skip_pkgs)
            elif cmd.function == 'builder':
                docker.build.build_pkg_builders(cmd.force)
            elif cmd.function == 'packages':
                docker.build.build_packages()
            elif cmd.function == 'containers':
                docker.build.build_containers(cmd.which, cmd.force)
        elif name == Cmds.unikernel:
            pass  # FIXME
        elif name == Cmds.test:
            test.test(num_nodes=cmd.nodes, debug=cmd.debug, tunnel=cmd.tunnel, force=cmd.force)
        elif name == Cmds.simulate:
            raise NotImplementedError
        elif name == Cmds.emulate:
            docker.emulate.emulate(num_nodes=cmd.nodes, debug=cmd.debug, tunnel=cmd.tunnel, force=cmd.force)
        elif name == Cmds.actuate:
            unikernel.actuate.actuate(num_nodes=cmd.nodes)


if __name__ == '__main__':
    cmd_struct = {
        Cmds.devel: Command(
            [Function('init', [], 'Prepare development environment for use'),
             Function('update', [], 'Update development environment'),
             ], [], 'Development environment'),
        Cmds.network: Command([], [], 'Prepare network for Docker/KVM'),
        Cmds.tag: Command([],
                          [Argument('--level', {'choices': ['major', 'minor', 'patch'], 'required': True,
                                                'help': 'Level of the version to increment'}),
                           ], 'Increment version, commit, and tag'),
        Cmds.docker: Command(
            [None,  # i.e. all
             Function('builder',
                      [Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'})],
                      'Build the package builder container'),
             Function('packages', [], 'Build the packages via a container'),
             Function('containers',
                      [Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'}),
                       Argument('--which', {'choices': ['packaged', 'devel', 'test'],
                                            'help': "build only this kind of container (default all)"}),
                       ],
                      'Build the docker containers'),
             ],
            [Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'}),
             Argument('--skip-pkgs', {'action': 'store_true', 'help': 'build everything except packages'})
             ], 'Build Docker container images'),
        Cmds.unikernel: Command([], [], 'Build unikernel images/filesystems'),
        Cmds.test: Command([],
                           [Argument('-n|--nodes', {'type': int, 'default': default_num_test_nodes}),
                            Argument('--debug', {'choices': ['all', 'build', 'run', 'remote'],
                                                 'help': 'debugging flags'}),
                            Argument('--tunnel', {'action': 'store_true', 'help': 'display over X11 tunnel'}),
                            Argument('--force', {'action': 'store_true', 'help': 'force builds (ignore cache)'}),
                            ], 'Run automated tests (using Docker)'),
        Cmds.simulate: Command([],
                               [Argument('-n|--nodes', {'type': int, 'default': default_num_simulate_nodes}),
                                ], 'Run AutonomousTrust simulation *(not implemented)*'),
        Cmds.emulate: Command([],
                              [Argument('-n|--nodes', {'type': int, 'default': default_num_emulate_nodes}),
                               Argument('--debug', {'choices': ['all', 'build', 'run', 'remote'],
                                                    'help': 'debugging flags'}),
                               Argument('--tunnel', {'action': 'store_true', 'help': 'display over X11 tunnel'}),
                               Argument('--force', {'action': 'store_true', 'help': 'force builds (ignore cache)'}),
                               ], 'Run AutonomousTrust instances in Docker'),
        Cmds.actuate: Command([],
                              [Argument('-n|--nodes', {'type': int, 'default': default_num_actuate_nodes}),
                               ], 'Run AutonomousTrust unikernel instances in QEMU/KVM'),
    }
    bare_args = [Argument('-v|--version', {'action': 'store_true', 'help': 'display program version and exit'}),
                 ]
    parser = CommandParser(prog, 'AutonomousTrust Development Tools', cmd_struct, bare_args)
    main(*parser.parse_args())

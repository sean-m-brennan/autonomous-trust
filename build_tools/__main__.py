# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from .command_parser import CommandParser, Command, Function, Argument
from .commands import tag, test
from .config import packages
from .cfg.validate import validate_packages
from . import program, util, devel, docker, unikernel

version = util.git_describe()[0]

default_num_test_nodes = 4
default_num_simulate_nodes = 20
default_num_emulate_nodes = 2
default_num_actuate_nodes = 2


class Cmds(object):
    devel = 'devel'
    network = 'network'
    tag = 'tag'
    venv = 'venv'
    distrib = 'distrib'
    docker = 'docker'
    unikernel = 'unikernel'
    test = 'test'
    simulate = 'simulate'
    emulate = 'emulate'
    actuate = 'actuate'


def main(commands, args):
    if args.version:
        print('%s version %s' % (program, version))
        return
    for name, cmd in commands.items():
        if name == Cmds.devel:
            if cmd.function == 'install':
                devel.init(cmd.conda, cmd.environ, cmd.basic, cmd.env_cfg)
            elif cmd.function == 'update':
                devel.update()
            elif cmd.function == 'validate':
                validate_packages()
        elif name == Cmds.network:
            pass  # FIXME
        elif name == Cmds.tag:
            tag.git_tag(cmd.level)
        elif name == Cmds.venv:
            docker.build.build_env_dir(cmd.env_dir)
        elif name == Cmds.distrib:
            docker.build.build_dist_repo(cmd.wheel)
        elif name == Cmds.docker:
            if cmd.function is None:
                docker.build.build(cmd.force, cmd.skip_pkgs)
            elif cmd.function == 'builder':
                docker.build.build_pkg_builders(cmd.force)
            elif cmd.function == 'packages':
                docker.build.build_packages()
            elif cmd.function == 'containers':
                docker.build.build_containers(pkg_name=cmd.pkg_name, which=cmd.which, debug=cmd.debug, force=cmd.force)
        elif name == Cmds.unikernel:
            unikernel.build.build_unikernel(initrdfs=cmd.initrdfs, do_clean=cmd.clean, pristine=cmd.pristine,
                                            debuggable=cmd.debug, force=cmd.force)
        elif name == Cmds.test:
            test.test(num_nodes=cmd.nodes, debug=cmd.debug, tunnel=cmd.tunnel, force=cmd.force,
                      quick=cmd.quick, shell=cmd.shell)
        elif name == Cmds.simulate:
            raise NotImplementedError
        elif name == Cmds.emulate:
            docker.emulate.emulate(num_nodes=cmd.nodes, debug=cmd.debug, devel=cmd.devel,
                                   tunnel=cmd.tunnel, force=cmd.force, quick=cmd.quick, shell=cmd.shell)
        elif name == Cmds.actuate:
            unikernel.actuate.actuate(num_nodes=cmd.nodes, initrdfs=cmd.initrdfs, quick=cmd.quick)


if __name__ == '__main__':
    cmd_struct = {
        Cmds.devel: Command(
            [Function('install',
                      [Argument('--conda', {'action': 'store_true', 'help': 'install only conda'}),
                       Argument('--environ', {'action': 'store_true', 'help': 'install only conda environment'}),
                       Argument('--env-cfg', {'action': 'store', 'help': 'specify a conda environment config',
                                              'type': str, 'default': ''}),
                       Argument('--basic', {'action': 'store_true', 'help': 'skip virtualization (Docker/QEMU/Unikraft'}),
                       ], 'Prepare development environment for use'),
             Function('update', [], 'Update development environment'),
             Function('validate', [], 'Validate development dependencies'),
             ], [], 'Development environment'),
        Cmds.network: Command([], [], 'Prepare network for Docker/KVM'),
        Cmds.tag: Command([],
                          [Argument('--level', {'choices': ['major', 'minor', 'patch'], 'required': True,
                                                'help': 'Level of the version to increment'}),
                           ], 'Increment version, commit, and tag'),
        Cmds.venv: Command([],
                           [Argument('--env-dir', {'action': 'store_true', 'help': 'Create venv here'}),
                           ], 'Build Python venv (for immediate use)'),
        Cmds.distrib: Command([],
                              [Argument('--wheel', {'action': 'store_true', 'help': 'Build wheel instead of sdist tarball'}),
                               ], 'Build Python dist (for pip install)'),
        Cmds.docker: Command(
            [None,  # i.e. all
             Function('builder',
                      [Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'}),
                       ],
                      'Build the package builder container'),
             Function('packages', [], 'Build the packages via a container'),
             Function('containers',
                      [Argument('--debug', {'choices': ['all', 'build', 'run', 'remote'],
                                            'help': 'debugging flags'}),
                       Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'}),
                       Argument('--pkg-name', {'choices': packages.keys(), 'help': 'build only this package'}),
                       Argument('--which', {'choices': ['packaged', 'devel', 'test'],
                                            'help': "build only this kind of container (default all)"}),
                       ],
                      'Build the docker containers'),
             ],
            [Argument('--force', {'action': 'store_true', 'help': 'force build (ignore cache)'}),
             Argument('--skip-pkgs', {'action': 'store_true', 'help': 'build everything except packages'})
             ], 'Build Docker container images'),
        Cmds.unikernel: Command([],
                                [Argument('--initrdfs', {'action': 'store_true', 'help': 'use initrd filesystem'}),
                                 Argument('--clean', {'action': 'store_true', 'help': 'clean up previous builds'}),
                                 Argument('--pristine', {'action': 'store_true', 'help': 'clean to pristine state'}),
                                 Argument('--debug', {'action': 'store_true', 'help': 'add debug symbols to image'}),
                                 Argument('--force', {'action': 'store_true', 'help': 'force rebuild'}),
                                 ], 'Build unikernel images/filesystems'),
        Cmds.test: Command([],
                           [Argument('-n|--nodes', {'type': int, 'default': default_num_test_nodes}),
                            Argument('--debug', {'choices': ['all', 'build', 'run', 'remote'],
                                                 'help': 'debugging flags'}),
                            Argument('--quick', {'action': 'store_true', 'help': 'do not rebuild, even if out of date'}),
                            Argument('--shell', {'action': 'store_true',
                                                 'help': 'get a shell in docker instead of running tests'}),
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
                               Argument('--devel', {'action': 'store_true', 'help': 'run the development image'}),
                               Argument('--quick', {'action': 'store_true', 'help':
                                                    'do not rebuild, even if out of date'}),
                               Argument('--shell', {'action': 'store_true',
                                                    'help': 'get a shell in docker instead of running the app'}),
                               Argument('--tunnel', {'action': 'store_true', 'help': 'display over X11 tunnel'}),
                               Argument('--force', {'action': 'store_true', 'help': 'force builds (ignore cache)'}),
                               ], 'Run AutonomousTrust instances in Docker'),
        Cmds.actuate: Command([],
                              [Argument('-n|--nodes', {'type': int, 'default': default_num_actuate_nodes}),
                               Argument('--quick', {'action': 'store_true', 'help':
                                                    'do not rebuild, even if out of date'}),
                               Argument('--initrdfs', {'action': 'store_true', 'help': 'use initrd filesystem'}),
                               ], 'Run AutonomousTrust unikernel instances in QEMU/KVM'),
    }
    bare_args = [Argument('-v|--version', {'action': 'store_true', 'help': 'display program version and exit'}),
                 ]
    parser = CommandParser(program, 'AutonomousTrust Development Tools', cmd_struct, bare_args)
    main(*parser.parse_args())

import sys
from collections import namedtuple
import argparse

Command = namedtuple('Command', 'functions arguments help')
Function = namedtuple('Function', 'name arguments help')
Argument = namedtuple('Argument', 'name args')


class ArgumentParams(dict):
    _allowed_keys = ['action', 'choices', 'const', 'default', 'dest', 'help', 'metavar', 'nargs', 'required', 'type']

    def __init__(self, **kwargs):
        super().__init__()
        for key in kwargs.keys():
            if key not in self._allowed_keys:
                raise KeyError(self._err_msg(key))
            self[key] = kwargs[key]

    def __setitem__(self, key, val):
        if key not in self._allowed_keys:
            raise KeyError(self._err_msg(key))
        dict.__setitem__(self, key, val)

    @classmethod
    def _err_msg(cls, key):
        return "key: '%s' is not an Argument parameter (one of: %s)" % (str(key), ', '.join(cls._allowed_keys))


class CommandParser(object):
    def __init__(self, program: str = sys.argv[0], description: str = '',
                 command_options: dict[str, Command] = None, bare_args: list[Argument] = None):
        if command_options is None:
            command_options = []
        if bare_args is None:
            bare_args = []

        self.arg_names = []
        for arg in bare_args:
            try:
                self.arg_names.append(arg.name.split('--')[1])
            except IndexError:
                raise argparse.ArgumentError(None, 'Incorrect format for option: %s' % arg)

        if len(sys.argv) < 2:
            sys.argv.append('-h')
        self.parser = argparse.ArgumentParser(prog=program, description=description)
        self._parse_args(self.parser, bare_args)
        subparser = self.parser.add_subparsers(dest='command', title='commands', metavar='')
        for cmd_name, cmd in command_options.items():
            cmd_parse = subparser.add_parser(cmd_name, help=cmd.help)
            self._parse_args(cmd_parse, cmd.arguments)
            subsubparser = cmd_parse.add_subparsers(dest='function', title='command functions', metavar='')
            for func in cmd.functions:
                if func is not None:
                    func_parse = subsubparser.add_parser(func.name, help=func.help)
                    self._parse_args(func_parse, func.arguments)

    @staticmethod
    def _parse_args(parser: argparse.ArgumentParser, arg_list: list[Argument]):
        for arg in arg_list:
            if '|' in arg.name:
                short, long = arg.name.split('|', 1)
                parser.add_argument(short, long, **arg.args)
            else:
                parser.add_argument(arg.name, **arg.args)

    def parse_args(self) -> tuple[dict[str, argparse.Namespace], argparse.Namespace]:
        argv = sys.argv[1:]
        commands = {}
        args = {}
        first = True
        while argv:
            options, argv = self.parser.parse_known_args(argv)
            opt_dict = vars(options)
            cmd = options.command
            if first:
                for k, v in list(opt_dict.items()):
                    if k in self.arg_names:
                        args[k] = v
                        del opt_dict[k]
                first = False
            commands[cmd] = argparse.Namespace(**opt_dict)
            if not options.command:
                break
        return commands, argparse.Namespace(**args)


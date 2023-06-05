import os
import subprocess


def _run_cmd(container_name: str, image_name: str, network_name: str, extra_args: list[str] = None,
             mounts: list[tuple[str, str]] = None, net_admin: bool = False, detached: bool = True) -> list[str]:
    if extra_args is None:
        extra_args = []
    if mounts is None:
        mounts = []
    cmd = ['docker', 'run']
    opts = ['--rm', '--name', container_name, '-h', container_name, '--network', network_name]
    if net_admin:
        opts += ['--cap-add', 'NET_ADMIN']
    if len(mounts) > 0:
        opts += ['-u', '%d:%d' % (os.getuid(), os.getgid())]
        for host_path, container_path in mounts:
            opts += ['-v', '%s:%s' % (host_path, container_path)]
    opts += list(extra_args)
    if detached:
        opts += ['-d']
    else:
        opts += ['-it']
    opts += [image_name]
    return cmd + opts


def run_container(container_name: str, image_name: str, network_name: str, extra_args: list[str] = None,
                  mounts: list[tuple[str, str]] = None, net_admin: bool = False, detached: bool = True) -> bool:
    cmd = _run_cmd(container_name, image_name, network_name, extra_args, mounts, net_admin, detached)
    p = subprocess.Popen(cmd)
    if p.returncode != 0:
        return False
    return True


def run_interactive_container(container_name: str, image_name: str, network_name: str, extra_args: list[str] = None,
                              mounts: list[tuple[str, str]] = None, net_admin: bool = False,
                              debug_run: bool = False, tunnel: bool = False, blocking: bool = False) -> bool:
    cmd = _run_cmd(container_name, image_name, network_name, extra_args, mounts, net_admin, detached=False)
    get_terminal(tunnel).run(' '.join(cmd), debug_run, blocking)
    return True


def get_terminal(tunnel=False):
    if 'unable to open display' in subprocess.getoutput('xhost'):
        raise RuntimeError('ERROR: Cannot open container terminals; try X11 forwarding.')
    if tunnel:
        if subprocess.call(['which', 'xterm'], stdout=subprocess.DEVNULL) == 0:
            return XTerm()
        raise RuntimeError('ERROR: need xterm for X11 tunnel, but xterm is missing.')
    else:
        if subprocess.call(['which', 'gnome-terminal'], stdout=subprocess.DEVNULL) == 0:
            return GnomeTerminal()
        elif subprocess.call(['which', 'qterminal'], stdout=subprocess.DEVNULL) == 0:
            return QTerminal()
        elif subprocess.call(['which', 'osascript'], stdout=subprocess.DEVNULL) == 0:
            return TerminalApp()
        raise NotImplementedError


class Terminal(object):
    debug_arg = "; exec bash"

    def run(self, command, debug=False, blocking=False):
        raise NotImplementedError


class XTerm(Terminal):
    def run(self, command, debug=False, blocking=False):
        if debug:
            command += self.debug_arg
        invocation = ['xterm', '-e', '/bin/sh', '-l', '-c', command]
        if not blocking:
            invocation += ['&']
        return subprocess.Popen(invocation)


class GnomeTerminal(Terminal):
    def run(self, command, debug=False, blocking=False):
        if debug:
            command += self.debug_arg
        invocation = ['gnome-terminal']
        options = ['--', '/bin/sh', '-c', command]
        if not blocking:
            options.insert(0, '--wait')
        return subprocess.Popen(invocation + options)


class QTerminal(Terminal):
    def run(self, command, debug=False, blocking=False):
        if debug:
            command += self.debug_arg
        invocation = ['qterminal', '-e', command]
        if not blocking:
            invocation += ['&']
        return subprocess.Popen(invocation)


class TerminalApp(Terminal):
    def run(self, command, debug=False, blocking=False):
        if debug:
            command += self.debug_arg
        tell = 'tell app "Terminal";  do script "%s"; end tell' % command
        invocation = ['osascript', '-e', tell]
        if not blocking:
            invocation += ['&']
        return subprocess.Popen(invocation)

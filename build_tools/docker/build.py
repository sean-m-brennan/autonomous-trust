import glob
import os
import shutil
import stat
import subprocess
import sys
import threading
from http.server import HTTPServer, CGIHTTPRequestHandler
from typing import Optional

from ..config import supported_platforms, base_dir, packages, images, wheels
from ..util import GREEN, RESET

REGISTRY_HOST = 'autonomous-trust.tekfive.com'
REGISTRY_PORT = 5000


def get_image_list():
    import docker as docker_iface
    client = docker_iface.from_env()
    return [i.tags[0].split(':')[0] for i in client.images.list() if len(i.tags) > 0]


def build(force=False, skip_pkgs=False):
    subprocess.run(['docker', 'images', 'prune'])
    if build_pkg_builders(force):
        if skip_pkgs or build_packages():
            return build_containers()
    return False


def build_pkg_builders(force: bool = False):
    src_dir = os.path.join(base_dir, 'src')
    print(GREEN + "Build package-builder containers" + RESET)
    # FIXME buildx needs troubleshooting
    # cmd = ['docker', 'buildx', 'build']
    cmd = ['docker', 'build']
    options = ['-t', 'package-builder', '-f', os.path.join(src_dir, 'Dockerfile-build'), src_dir]
    if 'buildx' in cmd:
        options = ['--platform', ','.join(supported_platforms)] + options
    if force:
        options.insert(0, '--no-cache')
    p = subprocess.run(cmd + options)
    if p.returncode != 0:
        raise RuntimeError('Package-builder container build failed')
    return True


def build_env_dir(env_dir: str = None, start_server: bool = True, quiet: bool = False):
    if env_dir is None:
        env_dir = os.path.join(base_dir, 'virtenv')
    if not os.path.exists(env_dir):
        os.makedirs(env_dir, exist_ok=True)
    build_dist_repo(wheel=True)
    subprocess.check_call([sys.executable, '-m', 'venv', env_dir])  # venv instead of --target

    if start_server:
        thread = threading.Thread(target=host_local_pypi)
        thread.daemon = True
        thread.start()
    extra = []
    if quiet:
        extra.append('-q')
    for pkg_name in packages:
        subprocess.check_call(['pip', 'install', '-I'] + extra + ['--extra-index-url', 'http://127.0.0.1:9000', pkg_name],
                              env={'PATH': os.path.join(env_dir, 'bin') + os.pathsep + os.environ['PATH']})


def host_local_pypi():
    os.chdir(os.path.join(base_dir, 'src', 'dist', 'pypi-repo'))
    httpd = HTTPServer(('', 9000), CGIHTTPRequestHandler)
    httpd.serve_forever()


def build_dist_repo(wheel: bool = False, quiet: bool = False):
    dist_dir = os.path.join(base_dir, 'src', 'dist', 'pypi-repo')
    if not os.path.exists(dist_dir):
        os.makedirs(dist_dir, exist_ok=True)
    host_script = os.path.join(dist_dir, 'host.sh')
    if not os.path.exists(host_script):
        with open(host_script, 'w') as script:
            script.write('#!/bin/sh\npython3 -m http.server 9000\n')
        st = os.stat(host_script)
        os.chmod(host_script, st.st_mode | stat.S_IEXEC)
    pip_config = os.path.join(sys.prefix, 'pip.conf')
    if not os.path.exists(pip_config):
        with open(pip_config, 'w') as cfg:
            cfg.write('[global]\nextra-index-url=http://127.0.0.1:9000\n')
    for pkg_name in packages:
        path = packages[pkg_name]
        img_name = images[pkg_name]
        fmt = 'sdist'
        if wheel or img_name in wheels:
            fmt = 'wheel'
        cmd = ['poetry', 'build-project', '--with-top-namespace=autonomous_trust', '-C', path, '-f', fmt, '-n']
        if quiet:
            cmd += ['-q']
        p = subprocess.run(cmd)
        if p.returncode != 0:
            raise RuntimeError('Package creation for %s failed' % img_name)
        for source in glob.glob(os.path.join(path, 'dist', '*.tar.gz')) + glob.glob(os.path.join(path, 'dist', '*.whl')):
            target_dir = os.path.join(dist_dir, img_name)
            os.makedirs(target_dir, exist_ok=True)
            target = os.path.join(target_dir, os.path.basename(source))
            shutil.move(source, target)
            try:
                os.rmdir(os.path.join(path, 'dist'))
            except (OSError, FileNotFoundError):
                pass


def build_packages():
    dist_dir = os.path.join(base_dir, 'src', 'dist', 'conda-repo')
    if not os.path.exists(dist_dir):
        os.makedirs(dist_dir, exist_ok=True)
    if 'package-builder' not in get_image_list():
        build_pkg_builders()
    for pkg_name in packages:
        img_name = images[pkg_name]
        path = packages[pkg_name]

        # FIXME buildx image naming
        for platform in supported_platforms:
            arch = platform.split('/')[-1]
            img_arch_name = img_name # + '-' + arch ?
            do_build = False
            if img_arch_name not in get_image_list():
                do_build = True
            else:
                pkg_search = os.path.join(dist_dir, '*', pkg_name + '-*.tar.bz2')
                pkgs = glob.glob(pkg_search)
                pkgs.sort()
                pkg_time = os.path.getmtime(pkgs[-1])
                src_time = max(os.path.getmtime(root) for root, _, _ in os.walk(path))
                if pkg_time < src_time:
                    do_build = True
            if do_build:
                print(GREEN + "Create %s package" % img_name + RESET)
                cmd = ['docker', 'run', '--rm', '-u', '%d:%d' % (os.getuid(), os.getgid()),
                       '-v', '%s:%s' % (path, '/build/src'), '-v', '%s:%s' % (dist_dir, '/build/dist'),
                       '-it', 'package-builder']
                p = subprocess.run(cmd)
                if p.returncode != 0:
                    raise RuntimeError('Package creation for %s failed' % img_name)
    return True


class Container(object):
    all = 'all'
    packaged = 'packaged'
    devel = 'devel'
    test = 'test'


def build_containers(pkg_name: Optional[str] = None, which: Container = Container.all,
                     debug: bool = False, force: bool = False):
    src_dir = os.path.join(base_dir, 'src')
    # FIXME ensure registry is running, otherwise start it (`docker compose src/docker-registry.yaml up -d`)

    package_list = [pkg_name]
    if pkg_name is None:
        package_list = packages.keys()
    for pkg_name in package_list:
        img_name = images[pkg_name]
        path = packages[pkg_name]

        packaged = ('', src_dir)
        devel = ('-devel', base_dir)
        test = ('-test', path)
        construct_list = [packaged, devel, test]
        if which == Container.packaged:
            construct_list = [packaged]
            if pkg_name not in get_image_list():
                build_packages()
        elif which == Container.devel:
            construct_list = [devel]
        elif which == Container.test:
            construct_list = [test]
            #if pkg_name + '-devel' not in get_image_list():
            #    construct_list.insert(0, devel)

        cmd = ['docker', 'build']
        extra = []
        if force:
            extra.append('--no-cache')
        if debug:
            extra.append('--progress=plain')

        for suffix, context in construct_list:
            target = img_name + suffix
            print()
            print(GREEN + "Build %s container" % target + RESET)
            options = extra + ['-t', target, '-f', os.path.join(path, 'Dockerfile' + suffix), context]
            p = subprocess.run(cmd + options)
            if p.returncode != 0:
                raise RuntimeError('Build of %s failed' % target)
            registry = '%s:%d/' % (REGISTRY_HOST, REGISTRY_PORT)
            p = subprocess.run(['docker', 'tag', target, registry + target])
            if p.returncode != 0:
                raise RuntimeError('Tag of %s failed' % target)
            p = subprocess.run(['docker', 'push', registry + target])
            if p.returncode != 0:
                raise RuntimeError('Push of %s failed' % target)
    return True

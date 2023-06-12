import os
import subprocess
import glob
import importlib.util

from ..config import base_dir
from ..util import GREEN, RESET, cat
from .cfg import uk_workdir

uk_dir = os.path.join(base_dir, 'unikernel')
lib_dir = os.path.join(base_dir, 'unikernel', 'lib')
extern_dir = os.path.join(base_dir, 'unikernel', 'extern')


def config_ext_libs(lib_list, kraft):
    import git
    os.makedirs(lib_dir, exist_ok=True)
    for lib in lib_list:
        if not os.path.isdir(os.path.join(lib_dir, lib)):
            print(GREEN + 'Initialize ' + lib + RESET)
            repo = git.Repo()
            reader = repo.config_reader()
            a_name = reader.get_value("user", "name")
            a_email = reader.get_value("user", "email")
            origin = cat(os.path.join(uk_dir, lib, 'origin'))
            version = cat(os.path.join(uk_dir, lib, 'version'))
            cmd = [kraft, 'lib', 'init', '--no-prompt', '--author-name', a_name, '--author-email', a_email,
                   '--origin', origin, '--version', version, lib]
            subprocess.run(cmd, cwd=lib_dir)
            subprocess.run(['rsync', '-a', '--exclude=version', '--exclude=origin',
                            os.path.join(uk_dir, lib) + '/', os.path.join(lib_dir, lib)])
            if not os.path.isdir(os.path.join(lib_dir, lib, '.git')):
                raise RuntimeError('ERROR: kraft init on %s failed' % lib)
            subprocess.run(['git', 'add', './*'], cwd=os.path.join(lib_dir, lib))
            subprocess.run(['git', 'commit', '-a', '-m', "Initial"], cwd=os.path.join(lib_dir, lib))
            subprocess.run([kraft, 'list', 'add', os.path.join(lib_dir, lib)])
        else:
            result = subprocess.run(['rsync', '-ai', '--exclude=version', '--exclude=origin',
                                     os.path.join(uk_dir, lib) + '/', os.path.join(lib_dir, lib)], capture_output=True)
            if result.stdout != '':
                print(GREEN + 'Update ' + lib + RESET)
                if not os.path.isdir(os.path.join(lib_dir, lib, '.git')):
                    raise RuntimeError('ERROR: original kraft init on %s failed - bad state detected' % lib)
                subprocess.run(['git', 'add', './*'], cwd=os.path.join(lib_dir, lib))
                subprocess.run(['git', 'commit', '-a', '-m', "Update"], cwd=os.path.join(lib_dir, lib))
                subprocess.run(['git', 'pull', 'origin', 'staging'],
                               cwd=os.path.join(uk_workdir, 'libs', lib))
        # FIXME
        #if os.path.exists(os.path.join(uk_dir, '.update')):
        #    os.remove(os.path.join(uk_dir, '.update'))


def get_ext_sources(impl):
    impl_dir = os.path.join(base_dir, 'unikernel', impl)
    os.makedirs(extern_dir, exist_ok=True)
    os.makedirs(os.path.join(impl_dir, 'build'), exist_ok=True)

    for cfg_file in glob.glob(os.path.join(impl_dir, 'extern_*_cfg.py')):
        mod_name = os.path.basename(cfg_file).split('_')[1]
        spec = importlib.util.spec_from_file_location(mod_name, cfg_file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print(GREEN + "Acquire sources for %s" % mod_name + RESET)
        mod.fetch_build(extern_dir, os.path.join(impl_dir, 'build'))

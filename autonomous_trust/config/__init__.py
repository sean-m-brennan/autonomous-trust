import os
from .configuration import Configuration, CfgIds, EmptyObject, to_yaml_string, from_yaml_string
from .generate import generate_identity


def random_config(base_dir, ident: str = None):
    if Configuration.VARIABLE_NAME in os.environ:
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.join(base_dir, Configuration.CFG_PATH)
        if ident is not None:
            cfg_dir = os.path.join(base_dir, ident, Configuration.CFG_PATH)
    if not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True, seed=ident)
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir

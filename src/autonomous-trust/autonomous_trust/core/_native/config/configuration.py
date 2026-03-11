# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""C-backed configuration helpers using libautonomous_trust."""

from .._ffi import ffi, lib

# Re-export Python Configuration classes for direct submodule imports
from ..._python.config.configuration import (  # noqa: F401
    Configuration, InitializableConfig, EmptyObject,
    SerializeMode, WireFormat,
    to_json_string, from_json_string,
    to_yaml_string, from_yaml_string,
    config_json_decoder, register_config_type,
)


def get_cfg_dir() -> str:
    """Return the configuration directory path (C implementation)."""
    path_buf = ffi.new('char[512]')
    rc = lib.get_cfg_dir(path_buf)
    if rc != 0:
        raise RuntimeError(f"get_cfg_dir failed with rc={rc}")
    return ffi.string(path_buf).decode('utf-8')


def get_data_dir() -> str:
    """Return the data directory path (C implementation)."""
    path_buf = ffi.new('char[512]')
    rc = lib.get_data_dir(path_buf)
    if rc != 0:
        raise RuntimeError(f"get_data_dir failed with rc={rc}")
    return ffi.string(path_buf).decode('utf-8')


def load_all_configs(cfg_dir: str, logger=None) -> dict:
    """Load all configuration files from a directory (C implementation).

    Args:
        cfg_dir: Path to configuration directory.
        logger: Optional logger_t pointer (CFFI cdata). If None, uses a
                default logger.

    Returns:
        Dictionary of config name -> config data.
    """
    from ..structures.map import Map

    configs_ptr = ffi.new('map_t **')
    configs_ptr[0] = ffi.cast('map_t *', 0x1)
    rc = lib.map_create(configs_ptr)
    if rc != 0:
        raise RuntimeError(f"map_create failed with rc={rc}")

    if logger is None:
        logger_ptr = ffi.NULL
    else:
        logger_ptr = logger

    dir_buf = ffi.new('char[]', cfg_dir.encode('utf-8'))
    rc = lib.load_all_configs(dir_buf, configs_ptr[0], logger_ptr)
    if rc != 0:
        lib.map_free(configs_ptr[0])
        raise RuntimeError(f"load_all_configs failed with rc={rc}")

    result = Map(_ptr=configs_ptr[0])
    return result

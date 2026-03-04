#!/usr/bin/env python3
"""One-shot migration script: convert .cfg.yaml files to .cfg.json and subsystems.yaml to subsystems.cfg.json.

Uses raw YAML parsing (not object construction) to avoid needing all packages installed.
"""

import json
import os
import sys
import glob
import base64
import re

import ruamel.yaml

base_dir = os.path.dirname(__file__)


def yaml_to_json_value(obj):
    """Recursively convert a ruamel.yaml-parsed object tree to JSON-compatible dicts with __type__ tags."""
    if isinstance(obj, ruamel.yaml.comments.CommentedMap):
        tag = str(obj.tag) if obj.tag else ''
        if tag.startswith('!Cfg:'):
            type_name = tag[len('!Cfg:'):]
            d = {'__type__': type_name}
            for k, v in obj.items():
                d[k] = yaml_to_json_value(v)
            return d
        elif tag == '!signedmessage':
            val = {}
            for k, v in obj.items():
                converted = yaml_to_json_value(v)
                if isinstance(converted, bytes):
                    val[k] = base64.b64encode(converted).decode('ascii')
                elif isinstance(converted, dict) and converted.get('__type__') == 'bytes':
                    val[k] = converted['__value__']
                else:
                    val[k] = converted
            return {'__type__': 'signedmessage', '__value__': val}
        else:
            return {k: yaml_to_json_value(v) for k, v in obj.items()}
    elif isinstance(obj, ruamel.yaml.comments.CommentedSeq):
        return [yaml_to_json_value(item) for item in obj]
    elif isinstance(obj, ruamel.yaml.scalarstring.ScalarString):
        tag = str(obj.tag) if hasattr(obj, 'tag') and obj.tag else ''
        if tag == '!datetime':
            return {'__type__': 'datetime', '__value__': str(obj)}
        if tag == '!timedelta':
            return {'__type__': 'timedelta', '__value__': str(obj)}
        if tag == '!UUID':
            return {'__type__': 'UUID', '__value__': str(obj)}
        if tag == '!Decimal':
            return {'__type__': 'Decimal', '__value__': str(obj)}
        return str(obj)
    elif isinstance(obj, bytes):
        return {'__type__': 'bytes', '__value__': base64.b64encode(obj).decode('ascii')}
    elif isinstance(obj, dict):
        return {k: yaml_to_json_value(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [yaml_to_json_value(item) for item in obj]
    else:
        return obj


def convert_tagged_yaml(filepath):
    """Parse YAML with tags preserved (round-trip mode) and convert to JSON with __type__ convention."""
    loader = ruamel.yaml.YAML(typ='rt')  # round-trip preserves tags

    with open(filepath, 'r') as f:
        data = loader.load(f)

    result = yaml_to_json_value(data)

    json_path = filepath.replace('.cfg.yaml', '.cfg.json')
    with open(json_path, 'w') as f:
        json.dump(result, f, indent=2)

    os.remove(filepath)
    print(f"  {os.path.relpath(filepath, base_dir)} -> {os.path.basename(json_path)}")
    return json_path


def convert_subsystems_yaml(filepath):
    """Convert a subsystems.yaml file to subsystems.cfg.json."""
    loader = ruamel.yaml.YAML(typ='rt')

    with open(filepath, 'r') as f:
        data = loader.load(f)

    # !!omap produces a CommentedMap or list of tuples
    if isinstance(data, ruamel.yaml.comments.CommentedMap):
        plain_dict = dict(data)
    elif isinstance(data, list):
        plain_dict = {}
        for item in data:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                plain_dict[item[0]] = item[1]
            elif isinstance(item, dict):
                plain_dict.update(item)
    elif isinstance(data, dict):
        plain_dict = data
    else:
        print(f"  WARNING: {filepath} has unexpected type {type(data)}, skipping")
        return None

    # Ensure all values are plain strings
    result = {str(k): str(v) for k, v in plain_dict.items()}

    json_path = os.path.join(os.path.dirname(filepath), 'subsystems.cfg.json')
    with open(json_path, 'w') as f:
        json.dump(result, f, indent=2)

    os.remove(filepath)
    print(f"  {os.path.relpath(filepath, base_dir)} -> {os.path.basename(json_path)}")
    return json_path


def main():
    print("Migrating .cfg.yaml files to .cfg.json ...")
    cfg_files = glob.glob(os.path.join(base_dir, 'examples', '**', '*.cfg.yaml'), recursive=True)
    for f in sorted(cfg_files):
        try:
            convert_tagged_yaml(f)
        except Exception as e:
            print(f"  ERROR converting {os.path.relpath(f, base_dir)}: {e}")

    print("\nMigrating subsystems.yaml files to subsystems.cfg.json ...")
    sub_files = glob.glob(os.path.join(base_dir, 'examples', '**', 'subsystems.yaml'), recursive=True)
    for f in sorted(sub_files):
        try:
            convert_subsystems_yaml(f)
        except Exception as e:
            print(f"  ERROR converting {os.path.relpath(f, base_dir)}: {e}")

    print("\nDone!")


if __name__ == '__main__':
    main()

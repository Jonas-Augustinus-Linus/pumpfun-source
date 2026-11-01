#!/usr/bin/env python3
"""Recompute this static packet without modifying source or binary inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-root', type=Path, default=HERE.parents[1])
    args = parser.parse_args()
    manifest = json.loads((HERE / 'manifest.json').read_text())
    for name, expected in manifest.items():
        assert Path(name).name == name
        assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, name
    spec = importlib.util.spec_from_file_location('fees_parser_attribution', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze(args.repository_root)
    assert actual == json.loads((HERE / 'analysis.json').read_text())
    print('PASS: packet hashes, encoded call chain, discriminator attribution, and guard shape')


if __name__ == '__main__':
    main()

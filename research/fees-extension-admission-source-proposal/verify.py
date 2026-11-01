#!/usr/bin/env python3
"""Verify ordinary source overrides and exact reversible patch; execute no targets."""
from pathlib import Path
import json
from source_tools import verify
if __name__ == '__main__':
    manifest, overrides = verify(Path(__file__).resolve().parent)
    print(json.dumps({'source_overrides_verified': len(overrides),
                     'before_source_inputs': len(manifest['before']),
                     'after_source_inputs': len(manifest['after']),
                     'full_source_materialized': False,
                     'runtime_verified': False, 'native_build_verified': False,
                     'whole_binary_identity_verified': False}, sort_keys=True))

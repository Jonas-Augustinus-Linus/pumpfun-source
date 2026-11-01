"""Verify this successor packet and replay the sealed parent capture offline."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / 'amm-sell-compiler-boundary-20261029'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def require(value, message):
    if not value:
        raise ValueError(message)


def inventory(root):
    return {p.relative_to(root).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
            for p in root.rglob('*') if p.is_file() and p.name != 'MANIFEST.json' and '__pycache__' not in p.parts}


def verify():
    require(inventory(HERE) == read(HERE / 'MANIFEST.json'), 'successor packet census/hash')
    inputs = read(HERE / 'inputs.json')
    require(sha((PARENT / 'MANIFEST.json').read_bytes()) == inputs['parent_manifest_sha256'], 'parent seal identity')
    require(inventory(PARENT) == read(PARENT / 'MANIFEST.json'), 'parent packet census/hash')
    compressed = (PARENT / inputs['capture']).read_bytes()
    require(sha(compressed) == inputs['capture_compressed_sha256'], 'compressed capture identity')
    raw = gzip.decompress(compressed)
    require(sha(raw) == inputs['capture_raw_sha256'], 'raw capture identity')
    spec = importlib.util.spec_from_file_location('ir_order_analysis', HERE / 'analyze.py')
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    result = analyzer.analyze(raw)
    require(result == read(HERE / 'analysis.json'), 'saved IR order replay')
    return result


if __name__ == '__main__':
    result = verify()
    print('PASS: successor and unchanged parent seals; all276 IR snapshots; adjacency first changes after SimplifyCFG; parent116 machine snapshots. No compiler or target execution.')

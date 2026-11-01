"""Verify saved captures with checks retained under Python -O and -OO."""
import argparse
import hashlib
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
SOURCE_HASHES = {
    'capture.py': {'78682d8dc87d1ee6ff864b0f19562bbbc8ca6a6a96306d99c32c9c3f3feb1fb4', '16b2a6e9f747dee5a964afae25d90cdd974d5da76e0db3fdfd4bf018fe80b5f5'},
    'analyze.py': {'6edfba06846ff9d6ba930867078acbbe25c88f6dedf0b1c5ab57da01384de4e6', 'dd7fb38d795d4dd72a25aab0d65c2223d9f6f75d8b3ecb0de1d87d6e102910ac'},
    'verify_evidence.py': {'95f9564d4b70985962f826e2b6a8a990ea665f39d698f43a50ae006bb61a4bed', 'de254298e2a064711f1709f5c7827fd34c2cca12af90504620e364c88d511c23'},
}


def checked_module(evidence_root=ROOT):
    sources = {}
    for name, expected in SOURCE_HASHES.items():
        path = ROOT / 'scripts' / name
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() not in expected:
            raise ValueError(f'Reviewed evidence helper has changed: {name}')
        sources[name] = raw.decode().replace('\r\n', '\n')
    modules = {}
    for name, source in sources.items():
        namespace = types.ModuleType('reviewed_' + name.replace('.', '_'))
        namespace.__file__ = str(ROOT / 'scripts' / name)
        if name == 'verify_evidence.py':
            imports = 'from capture import b58\nfrom analyze import elf_layout\n'
            if source.count(imports) != 1:
                raise ValueError('Reviewed evidence imports no longer apply')
            source = source.replace(imports, '', 1)
            namespace.b58 = modules['capture.py'].b58
            namespace.elf_layout = modules['analyze.py'].elf_layout
        # Explicitly retain assertions in both the gate and its ELF dependency.
        exec(compile(source, namespace.__file__, 'exec', optimize=0), namespace.__dict__)
        modules[name] = namespace
    gate = modules['verify_evidence.py']
    gate.ROOT = Path(evidence_root).resolve()
    return gate


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path, default=ROOT,
                        help='Repository-shaped root containing evidence/; defaults to this checkout')
    args = parser.parse_args()
    checked_module(args.evidence_root).main()

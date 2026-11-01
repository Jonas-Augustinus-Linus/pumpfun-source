"""Validate loader option/observation domains before the existing byte gate."""
import argparse
import hashlib
import json
from pathlib import Path
import types

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research/evidence-checks-optimized-python/verify.py'
REVIEWED={'4eb485783844a8641e24a95fb20d9fd0aa768049a88b2a357172f2bfe575a06e',
          '5102a4c8dd649bd76ce52116f9278caf9345dc92a5f8d4e50130d507001efd25'}


class LoaderDomainError(ValueError):
    pass


def byte_gate(root):
    raw=BASE.read_bytes()
    if hashlib.sha256(raw).hexdigest() not in REVIEWED:
        raise ValueError('Reviewed optimization-safe verifier changed')
    module=types.ModuleType('reviewed_optimized_evidence')
    module.__file__=str(BASE)
    exec(compile(raw.decode('utf-8'),str(BASE),'exec',optimize=0),module.__dict__)
    return module.checked_module(root)


def verify(root=ROOT):
    root=Path(root).resolve()
    gate=byte_gate(root)
    for path in sorted((root/'evidence').glob('**/capture.json')):
        metadata=json.loads(path.read_text(encoding='utf-8'))
        legacy=metadata.get('loader')=='legacy-v2'
        slots=metadata.get('context_slots')
        expected=2 if legacy else 4
        if not isinstance(slots,list) or len(slots)!=expected or any(type(slot) is not int or not 0<=slot<2**64 for slot in slots):
            raise LoaderDomainError(f'{path.parent.name}: expected {expected} uint64 observation slots')
        if slots!=sorted(slots):
            raise LoaderDomainError(f'{path.parent.name}: observation slots out of order')
        if not legacy:
            data=(path.parent/'programdata-account.bin').read_bytes()
            if len(data)<45 or data[12] not in (0,1):
                raise LoaderDomainError(f'{path.parent.name}: invalid upgrade-authority option tag')
    return gate.main()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,default=ROOT)
    verify(parser.parse_args().evidence_root)

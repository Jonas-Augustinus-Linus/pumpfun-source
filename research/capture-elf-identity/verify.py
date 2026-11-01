"""Check the retained ELF64 Solana identity before the existing layout gate."""
import argparse
import hashlib
from pathlib import Path
import struct
import types

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'research/evidence-checks-optimized-python/verify.py'
REVIEWED={'4eb485783844a8641e24a95fb20d9fd0aa768049a88b2a357172f2bfe575a06e',
          '5102a4c8dd649bd76ce52116f9278caf9345dc92a5f8d4e50130d507001efd25'}


class ElfIdentityError(ValueError):pass


def check_identity(data):
    if len(data)<64:raise ElfIdentityError('truncated ELF64 header')
    if data[:7]!=b'\x7fELF\x02\x01\x01':raise ElfIdentityError('expected current-version little-endian ELF64 identification')
    kind,machine,version=struct.unpack_from('<HHI',data,16)
    if kind!=3:raise ElfIdentityError('expected retained ET_DYN program image')
    # Retained legacy BPF captures use 247; current SBPF captures use 263.
    if machine not in (247,263):raise ElfIdentityError('unsupported captured ELF machine')
    if version!=1:raise ElfIdentityError('expected ELF header version 1')
    if struct.unpack_from('<H',data,52)[0]!=64:raise ElfIdentityError('expected 64-byte ELF header size')


def byte_gate(root):
    raw=BASE.read_bytes()
    if hashlib.sha256(raw).hexdigest() not in REVIEWED:raise ValueError('Reviewed optimization-safe verifier changed')
    module=types.ModuleType('reviewed_optimized_evidence');module.__file__=str(BASE)
    exec(compile(raw.decode('utf-8'),str(BASE),'exec',optimize=0),module.__dict__)
    return module.checked_module(root)


def verify(root=ROOT):
    gate=byte_gate(Path(root).resolve())
    original_layout=gate.elf_layout
    def checked_layout(data):
        check_identity(data)
        return original_layout(data)
    gate.elf_layout=checked_layout
    return gate.main()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,default=ROOT)
    verify(parser.parse_args().evidence_root)

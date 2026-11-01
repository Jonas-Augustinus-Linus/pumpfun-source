"""Check declared capture identity fields the byte verifier does not read.

scripts/verify_evidence.py hashes payloads and checks loader metadata that is
stored in the account bytes. It does not read capture.json program, owner, or
commitment. Those fields can be replaced without a byte change.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/verify_evidence.py'
HELPER_SHA256 = {
    'de254298e2a064711f1709f5c7827fd34c2cca12af90504620e364c88d511c23',
    '95f9564d4b70985962f826e2b6a8a990ea665f39d698f43a50ae006bb61a4bed',
}
LEGACY_OWNER = 'BPFLoader2111111111111111111111111111111111'
UPGRADEABLE_OWNER = 'BPFLoaderUpgradeab1e11111111111111111111111'
# Addresses from docs/SCOPE.md. Folder names are the evidence layout.
PROGRAMS = {
    'evidence/original/pump': '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P',
    'evidence/original/pump_amm': 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA',
    'evidence/original/pump_fees': 'pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ',
    'evidence/original/mayhem': 'MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e',
    'evidence/dependencies/spl_token': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    'evidence/dependencies/spl_token_2022': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
    'evidence/dependencies/associated_token': 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
    'evidence/dependencies/token_metadata': 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',
    'evidence/dependencies/donation_relay': 'RLAYHr9TRFcKB2ubYQhspcnXiaGpaVzNQvHytt47RZu',
}


class IdentityError(ValueError):
    pass


def require_archived_helper():
    raw = HELPER.read_bytes()
    text = raw.replace(b'\r\n', b'\n')
    forms = {
        hashlib.sha256(text).hexdigest(),
        hashlib.sha256(text.replace(b'\n', b'\r\n')).hexdigest(),
    }
    digest = hashlib.sha256(raw).hexdigest()
    if forms != HELPER_SHA256 or digest not in HELPER_SHA256:
        raise IdentityError('The reviewed evidence verifier has changed')
    source = text.decode()
    if "['program']" in source or 'commitment' in source:
        raise IdentityError('The archived verifier now reads identity fields')
    return digest


def check(root):
    root = Path(root)
    require_archived_helper() if root == ROOT else None
    scope = (ROOT / 'docs/SCOPE.md').read_text(encoding='utf-8')
    for address in PROGRAMS.values():
        if address not in scope:
            raise IdentityError('SCOPE.md no longer contains ' + address)
    failures = []
    for folder, address in PROGRAMS.items():
        path = root / folder / 'capture.json'
        if not path.is_file():
            failures.append(folder + ' capture.json missing')
            continue
        record = json.loads(path.read_text(encoding='utf-8'))
        if record.get('program') != address:
            failures.append(folder + ' program id')
        if record.get('commitment') != 'finalized':
            failures.append(folder + ' commitment')
        expected_owner = LEGACY_OWNER if record.get('loader') == 'legacy-v2' else UPGRADEABLE_OWNER
        if record.get('owner') != expected_owner:
            failures.append(folder + ' owner')
    if failures:
        raise IdentityError('Declared capture identity mismatch: ' + ', '.join(failures))
    return len(PROGRAMS)


def main():
    # The archived helper hash is checked only for the repository copy.
    digest = require_archived_helper()
    count = check(ROOT)
    print(f'{count} capture identity fields verified; archived helper {digest[:12]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

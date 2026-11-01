"""Packet verifiers must check the folder, not only the files their manifest names.

Every packet under `research/` pins its files in `MANIFEST.json` and its verifier
hashes the entries the manifest lists. A file the packet ships with no entry is
never named, so it is never hashed: the packet carries it, the record does not
mention it, and the verifier still reports success.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / 'research'
PACKET = RESEARCH / 'pump-trade-cu-scaling-20261030'
MARKER = 'packet file set differs from MANIFEST.json'
WALKS = ('rglob(', 'iterdir(', 'os.walk(', 'os.scandir(')


def verifiers():
    for path in sorted(RESEARCH.glob('*/verify.py')):
        text = path.read_text(encoding='utf-8')
        if 'MANIFEST.json' in text:
            yield path, text


def run(packet):
    return subprocess.run(
        [sys.executable, '-B', str(packet / 'verify.py'),
         '--images', json.dumps({'original': '/nonexistent/original.so',
                                 'candidate': '/nonexistent/candidate.so'})],
        cwd=packet, capture_output=True, text=True)


class PacketManifestCensus(unittest.TestCase):
    def test_every_manifest_verifier_walks_its_packet(self):
        """A verifier that trusts MANIFEST.json has to compare it with the folder."""
        missing = [str(path.relative_to(ROOT)) for path, text in verifiers()
                   if not any(walk in text for walk in WALKS)]
        self.assertEqual([], missing)

    def test_unlisted_file_is_refused_before_any_image_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(PACKET, packet)
            (packet / 'runtime' / 'unlisted.bin').write_bytes(b'\x00')
            result = run(packet)
        self.assertEqual(1, result.returncode)
        self.assertIn(MARKER, result.stdout + result.stderr)
        self.assertIn('runtime/unlisted.bin', result.stdout + result.stderr)
        # Stopped at the packet, not at the missing images handed to it.
        self.assertNotIn('Nonexistent', result.stdout + result.stderr)
        self.assertNotIn('/nonexistent/', result.stdout + result.stderr)

    def test_pristine_packet_reaches_the_image_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(PACKET, packet)
            result = run(packet)
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        self.assertIn('/nonexistent/', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

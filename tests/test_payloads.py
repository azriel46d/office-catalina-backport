import os
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import patcher


class RejectionTests(unittest.TestCase):
    def test_unknown_inputs_rejected(self):
        with self.assertRaises(ValueError):
            patcher.build_mso30(b'not a Microsoft framework')
        with self.assertRaises(ValueError):
            patcher.build_mso99(b'not a Microsoft framework', b'not a certificate')


@unittest.skipUnless(os.environ.get('OFFICE_TEST_FIXTURES'), 'Proprietary fixtures are not distributed')
class RealPayloadTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ['OFFICE_TEST_FIXTURES'])
        self.cert = (self.root / 'backport/certs/new_53e06022bfaa.der').read_bytes()

    def test_exact_outputs_both_builds(self):
        for build, suffix in [('16.66.22101101', ''), ('16.65.22091101', '-16.65')]:
            profile = patcher.PROFILES[build]
            for name in ['mso99', 'mso30']:
                original = (self.root / 'binaries' / (name + suffix)).read_bytes()
                result = patcher.build_mso99(original, self.cert) if name == 'mso99' else patcher.build_mso30(original)
                self.assertEqual(patcher.digest(result), profile['patched'][name])
                self.assertEqual(len(result), len(original))
                # ARM64 and everything after the x86 patch region remain untouched.
                end = profile['cert_offset'] + 4704 if name == 'mso99' else 0x4000 + profile['header_end']
                self.assertEqual(original[end:], result[end:])
                changed = bytearray(original)
                changed[-1] ^= 1
                with self.assertRaises(ValueError):
                    patcher.build_mso99(changed, self.cert) if name == 'mso99' else patcher.build_mso30(changed)
                with self.assertRaises(ValueError):
                    patcher.build_mso99(result, self.cert) if name == 'mso99' else patcher.build_mso30(result)

    def test_wrong_certificate_rejected(self):
        original = (self.root / 'binaries/mso99').read_bytes()
        with self.assertRaises(ValueError):
            patcher.build_mso99(original, b'wrong certificate')


if __name__ == '__main__':
    unittest.main()

"""Filesystem transaction tests use synthetic data, never Microsoft files."""
import argparse
import copy
import json
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import patcher
import suite


class TransactionTests(unittest.TestCase):
    def exercise(self, fail_second):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'Applications'
            app = root / 'Microsoft Word.app'
            executable = app / 'Contents/MacOS/Microsoft Word'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'unchanged main executable')
            originals = {'mso99': b'original99', 'mso30': b'original30'}
            hashes = {n: patcher.digest(b) for n, b in originals.items()}
            for n, b in originals.items():
                f = app / patcher.REL[n]
                f.parent.mkdir(parents=True)
                f.write_bytes(b)
            certificate = Path(temp) / 'public-ca.der'
            certificate.write_bytes(b'synthetic certificate')
            backup = Path(temp) / 'backup'
            record = {'app': app.name, 'profile': '16.66.22101101',
                      'original_sha256': hashes, 'executable': 'Microsoft Word',
                      'main_sha256': patcher.file_hash(executable)}
            args = argparse.Namespace(applications_dir=root, certificate=certificate, backup_dir=backup)
            real_rename = Path.rename

            def rename(path, target):
                if fail_second and path.name == 'mso30.patched.framework':
                    raise OSError('injected replacement failure')
                return real_rename(path, target)

            def command(argv):
                if str(argv[0]) == '/usr/bin/ditto':
                    shutil.copytree(argv[1], argv[2], symlinks=True)

            entitlement = plistlib.dumps({'com.apple.security.cs.disable-library-validation': True})
            with mock.patch.object(suite, 'check_platform'), \
                 mock.patch.object(suite, 'ensure_closed'), \
                 mock.patch.object(suite, 'scan', side_effect=lambda _: [copy.deepcopy(record)]), \
                 mock.patch.object(patcher, 'run', side_effect=command), \
                 mock.patch.object(patcher, 'build_mso99', return_value=b'patched99'), \
                 mock.patch.object(patcher, 'build_mso30', return_value=b'patched30'), \
                 mock.patch.object(patcher, 'CERT_HASH', patcher.digest(certificate.read_bytes())), \
                 mock.patch.dict(patcher.PROFILES['16.66.22101101'], {'original': hashes}), \
                 mock.patch.object(suite.subprocess, 'run', return_value=mock.Mock(stdout=entitlement)), \
                 mock.patch.object(Path, 'rename', rename):
                if fail_second:
                    with self.assertRaises(OSError):
                        suite.apply(args)
                    self.assertEqual(json.loads((backup / 'receipt.json').read_text())['state'], 'restored')
                else:
                    suite.apply(args)
                    suite.verify(args)
                    self.assertEqual((app / patcher.REL['mso99']).read_bytes(), b'patched99')
                    suite.restore(args)
                for n, b in originals.items():
                    self.assertEqual((app / patcher.REL[n]).read_bytes(), b)
                self.assertEqual(executable.read_bytes(), b'unchanged main executable')

    def test_apply_verify_restore(self):
        self.exercise(False)

    def test_partial_swap_failure_restores_both_frameworks(self):
        self.exercise(True)


if __name__ == '__main__':
    unittest.main()

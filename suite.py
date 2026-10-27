#!/usr/bin/env python3
"""Inspect, patch, verify or restore supported Office apps in place."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import patcher as core

APPS = ['Microsoft Word.app', 'Microsoft Excel.app', 'Microsoft PowerPoint.app',
        'Microsoft Outlook.app', 'Microsoft OneNote.app']


def framework(app, name):
    return app / 'Contents/Frameworks' / (name + '.framework')


def binary(framework_path, name):
    return framework_path / 'Versions/A' / name


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    with temporary.open('rb') as f:
        os.fsync(f.fileno())
    os.replace(temporary, path)


def ensure_closed(apps):
    # Fail closed on a running installed app; do not terminate it or risk unsaved work.
    result = subprocess.run(['/bin/ps', '-axo', 'command='], check=True, capture_output=True, text=True)
    for app in apps:
        with (app / 'Contents/Info.plist').open('rb') as f:
            executable = plistlib.load(f)['CFBundleExecutable']
        core.require(str(app / 'Contents/MacOS' / executable) not in result.stdout,
                     'Quit ' + app.name + ' before continuing. No app is forcibly closed.')


def scan(root):
    records = []
    for name in APPS:
        app = root / name
        if not app.exists():
            continue
        core.require(not app.is_symlink(), 'Symlink app not supported: ' + str(app))
        with (app / 'Contents/Info.plist').open('rb') as f:
            info = plistlib.load(f)
        hashes = {n: core.file_hash(app / rel) for n, rel in core.REL.items()}
        profile_name = next((k for k, v in core.PROFILES.items() if hashes == v['original']), None)
        core.require(profile_name is not None, name + ': unsupported/modified frameworks; entire operation stopped.')
        core.require(info.get('CFBundleVersion') == profile_name, name + ': unexpected app build.')
        executable = info['CFBundleExecutable']
        core.require('/' not in executable and executable not in ('.', '..'), 'Invalid executable name.')
        for n in core.REL:
            fw = framework(app, n)
            core.require(not fw.is_symlink() and not binary(fw, n).is_symlink(), 'Symlink framework/binary unsupported.')
        records.append({'app': name, 'profile': profile_name, 'original_sha256': hashes,
                        'executable': executable, 'main_sha256': core.file_hash(app / 'Contents/MacOS' / executable)})
    core.require(records, 'No supported Office apps found.')
    return records


def check_platform():
    core.mac_only()
    core.require(platform.machine() == 'x86_64', 'Intel Macs only; ARM64 patching is not supported.')


def inspect(args):
    check_platform()
    records = scan(args.applications_dir.expanduser().resolve())
    for r in records:
        print(r['app'] + ': supported exact build ' + r['profile'])
    print('Read-only inspection; all installed Office apps must pass before suite apply.')


def load_receipt(backup):
    receipt = json.loads((backup / 'receipt.json').read_text())
    core.require(receipt['format'] == 1, 'Unsupported backup receipt.')
    root = Path(receipt['applications_dir'])
    core.require(root.is_absolute(), 'Invalid application root.')
    for r in receipt['apps']:
        core.require(r['app'] in APPS and r['profile'] in core.PROFILES, 'Invalid backup app/profile.')
        core.require('/' not in r['executable'], 'Invalid executable path.')
    return receipt, root


def restore_records(backup, receipt, root, changed_only=False):
    for r in reversed(receipt['apps']):
        app = root / r['app']
        for n in reversed(list(core.REL)):
            if changed_only and n not in r.get('changing', []):
                continue
            saved = backup / r['app'] / (n + '.original.framework')
            core.require(core.file_hash(binary(saved, n)) == core.PROFILES[r['profile']]['original'][n], 'Backup hash mismatch.')
            core.run(['/usr/bin/codesign', '--verify', '--strict', saved])
            destination = framework(app, n)
            parent = destination.parent
            tmp = Path(tempfile.mkdtemp(prefix='.office-restore-', dir=str(parent)))
            try:
                replacement = tmp / (n + '.framework')
                core.run(['/usr/bin/ditto', saved, replacement])
                old = tmp / 'previous.framework'
                if destination.exists():
                    destination.rename(old)
                try:
                    replacement.rename(destination)
                except BaseException:
                    if old.exists():
                        old.rename(destination)
                    raise
                core.run(['/usr/bin/codesign', '--verify', '--strict', destination])
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        core.require(core.file_hash(app / 'Contents/MacOS' / r['executable']) == r['main_sha256'], 'Main executable changed independently.')
    receipt['state'] = 'restored'
    save(backup / 'receipt.json', receipt)


def apply(args):
    check_platform()
    root = args.applications_dir.expanduser().resolve()
    records = scan(root)
    ensure_closed([root / r['app'] for r in records])
    cert = args.certificate.expanduser().resolve().read_bytes()
    core.require(core.digest(cert) == core.CERT_HASH, 'Wrong CA; use patcher.py prepare-donor.')
    backup = args.backup_dir.expanduser().absolute()
    core.require(not backup.exists() and not backup.is_symlink(), 'Backup directory must be new.')
    # Preflight every app/signature and all destination permissions before writing.
    for r in records:
        app = root / r['app']
        core.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
        entitlements = subprocess.run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)],
                                      check=True, capture_output=True).stdout
        start = entitlements.find(b'<?xml')
        core.require(start >= 0, 'Cannot inspect original app entitlements.')
        values = plistlib.loads(entitlements[start:])
        core.require(values.get('com.apple.security.cs.disable-library-validation') is True,
                     r['app'] + ': existing entitlement does not permit modified frameworks.')
        core.require(os.access(app / 'Contents/Frameworks', os.W_OK), 'Administrator access needed; run suite apply with sudo.')
        core.require(app not in backup.resolve().parents, 'Backup cannot be inside an app.')
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.mkdir(mode=0o700)
    receipt = {'format': 1, 'patcher_version': core.VERSION, 'applications_dir': str(root),
               'created_utc': datetime.datetime.utcnow().isoformat() + 'Z', 'state': 'preparing', 'apps': records}
    save(backup / 'receipt.json', receipt)
    try:
        # Prepare all signed replacements before touching any installed framework.
        for r in records:
            app = root / r['app']
            work = backup / r['app']
            work.mkdir()
            for n, rel in core.REL.items():
                saved = work / (n + '.original.framework')
                staged = work / (n + '.patched.framework')
                core.run(['/usr/bin/ditto', framework(app, n), saved])
                core.require(core.file_hash(binary(saved, n)) == r['original_sha256'][n], 'Source changed during backup.')
                core.run(['/usr/bin/codesign', '--verify', '--strict', saved])
                core.run(['/usr/bin/ditto', saved, staged])
                original = binary(saved, n).read_bytes()
                patched = core.build_mso99(original, cert) if n == 'mso99' else core.build_mso30(original)
                binary(staged, n).write_bytes(patched)
                core.run(['/usr/bin/codesign', '--force', '--sign', '-', staged])
                core.run(['/usr/bin/codesign', '--verify', '--strict', staged])
                r.setdefault('installed_sha256', {})[n] = core.file_hash(binary(staged, n))
            save(backup / 'receipt.json', receipt)
        ensure_closed([root / r['app'] for r in records])
        core.require(scan(root) == [dict((k, v) for k, v in r.items() if k != 'installed_sha256') for r in records], 'App changed while staging.')
        receipt['state'] = 'installing'
        save(backup / 'receipt.json', receipt)
        for r in records:
            app = root / r['app']
            for n in core.REL:
                destination = framework(app, n)
                work = backup / r['app']
                staged = work / (n + '.patched.framework')
                # Rename within the same filesystem; fail before replacement if unsupported.
                core.require(staged.stat().st_dev == destination.stat().st_dev, 'Backup must be on the same filesystem as Office.')
                previous = work / (n + '.previous.framework')
                r.setdefault('changing', []).append(n)
                save(backup / 'receipt.json', receipt)
                destination.rename(previous)
                staged.rename(destination)
                core.run(['/usr/bin/codesign', '--verify', '--strict', destination])
            core.require(core.file_hash(app / 'Contents/MacOS' / r['executable']) == r['main_sha256'], 'Main executable changed.')
        receipt['state'] = 'installed'
        save(backup / 'receipt.json', receipt)
        for r in records:
            for n in core.REL:
                shutil.rmtree(backup / r['app'] / (n + '.previous.framework'))
        print('Patched in place:', ', '.join(r['app'] for r in records))
        print('Restorable backup:', backup)
        print('Open your normal Office apps. Activation/renewal still requires a legitimate account.')
    except BaseException:
        if any(r.get('changing') for r in records):
            print('Installation failed; restoring affected frameworks from backups.', file=sys.stderr)
            restore_records(backup, receipt, root, changed_only=True)
        else:
            receipt['state'] = 'not-installed'
            save(backup / 'receipt.json', receipt)
        raise


def verify(args):
    check_platform()
    backup = args.backup_dir.expanduser().resolve()
    receipt, root = load_receipt(backup)
    core.require(receipt['state'] == 'installed', 'Receipt does not describe a completed installation.')
    for r in receipt['apps']:
        app = root / r['app']
        for n, rel in core.REL.items():
            core.require(core.file_hash(app / rel) == r['installed_sha256'][n], r['app'] + ': framework changed.')
            core.run(['/usr/bin/codesign', '--verify', '--strict', framework(app, n)])
        core.require(core.file_hash(app / 'Contents/MacOS' / r['executable']) == r['main_sha256'], 'Main executable changed.')
        print(r['app'] + ': patched files match receipt; main executable unchanged.')
    print('This verifies installed files, not activation or future renewal.')


def restore(args):
    check_platform()
    backup = args.backup_dir.expanduser().resolve()
    receipt, root = load_receipt(backup)
    core.require(receipt['state'] in ('installed', 'installing'), 'Backup is not an installed/interrupted patch.')
    ensure_closed([root / r['app'] for r in receipt['apps']])
    # Avoid undoing an unrelated Office update. Interrupted installs may have a missing framework.
    for r in receipt['apps']:
        app = root / r['app']
        core.require(core.file_hash(app / 'Contents/MacOS' / r['executable']) == r['main_sha256'], 'App was updated; refusing rollback over it.')
        for n, rel in core.REL.items():
            if (app / rel).exists():
                current = core.file_hash(app / rel)
                core.require(current in (r['original_sha256'][n], r['installed_sha256'][n]), 'Framework changed independently; refusing rollback.')
    restore_records(backup, receipt, root)
    print('Original frameworks restored. Backups retained:', backup)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for command, func in [('inspect', inspect), ('apply', apply), ('verify', verify), ('restore', restore)]:
        q = sub.add_parser(command)
        if command in ('inspect', 'apply'):
            q.add_argument('--applications-dir', type=Path, default=Path('/Applications'))
        if command != 'inspect':
            q.add_argument('--backup-dir', type=Path, required=True)
        if command == 'apply':
            q.add_argument('--certificate', type=Path, required=True)
        q.set_defaults(func=func)
    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)

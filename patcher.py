#!/usr/bin/env python3
"""Exact-build Office compatibility primitives and optional Word test-copy workflow."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile

VERSION = '1.0.0'
PACKAGE_URL = 'https://officecdn.microsoft.com/pr/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/Microsoft_Word_16.83.24031120_Updater.pkg'
PACKAGE_HASH = '6155783198cebc67706b40505f27aeeb442c0c9eb108e47428578e826f41a2f6'
DONOR_HASH = '60fb321a30f2b116dfa1ee278628920fd0cd691dc58fb4a1891a9390dfa017b8'
CERT_HASH = '53e06022bfaa603f0fdb18ff193a93075e815a4359c1694d83adc616efbbb29c'
ORIGINAL = {
    'mso99': '1402eab4d8b61cbfb06170ca7d7a0cffdfa8734dda6d42e146d724b1946cb865',
    'mso30': '9712aff68e0f7ca6d01076be901d90aaa67ccb84cb7fc7cd5fde92458d39edad',
}
PATCHED = {
    'mso99': 'e254a2ca742f49993170f8f93f779919e6f54f893f747ca7419ab7b28c5abcb2',
    'mso30': '25b87aa2d643c4af7bf53bfc7c0ebf59384b9e294473e9ac00cc054596c05a57',
}
PROFILES = {
    '16.66.22101101': {'original': ORIGINAL, 'patched': PATCHED,
        'cert_offset': 0x1a8e1a0, 'length_offset': 0x10887a,
        'header_start': 0xeee24, 'header_end': 0xeee43, 'constructor': 0x65d19c,
        'expected': '4889c74889deba14000000e850327900488dbdd8f9ffff4889dee859e35600'},
    '16.65.22091101': {
        'original': {'mso99': 'c5d7f114403efe998bfc96309e166bd39c9198be5de00ada5345b4970110c73d',
                     'mso30': '9026f8f7c64e587787810053307c2d87011b86f590d2fa62d6ed7eac78f1b4d8'},
        'patched': {'mso99': '95df04e82d24c73252bb47bcb0607536800e134985236e4c87e346b1657859ca',
                    'mso30': 'fee4c016394a715f917df12587f2bfdba1199c25256ecfa52b0549e29e2be395'},
        'cert_offset': 0x1a8f080, 'length_offset': 0x1076f4,
        'header_start': 0x104f54, 'header_end': 0x104f73, 'constructor': 0x6747bc,
        'expected': '4889c74889deba14000000e82c3d7900488dbdd8f9ffff4889dee849f85600'},
}


def binary_profile(name, data):
    actual = digest(data)
    for profile in PROFILES.values():
        if actual == profile['original'][name]:
            return profile
    raise ValueError('Unsupported or modified ' + name + '; no files changed.')


REL = {n: Path('Contents/Frameworks') / (n + '.framework') / 'Versions/A' / n for n in ORIGINAL}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(args):
    subprocess.run([str(a) for a in args], check=True)


def mac_only():
    require(sys.platform == 'darwin', 'This command requires macOS.')


def originals(app):
    require((app / 'Contents/MacOS/Microsoft Word').is_file(), 'Not a Microsoft Word app bundle.')
    data = {n: (app / rel).read_bytes() for n, rel in REL.items()}
    for n, b in data.items():
        binary_profile(n, b)
    return data


def x86_offset(data):
    require(data[:4] == bytes.fromhex('cafebabe'), 'Expected FAT32 Mach-O.')
    for i in range(struct.unpack_from('>I', data, 4)[0]):
        cpu, _, offset, size, _ = struct.unpack_from('>IIIII', data, 8 + i * 20)
        if cpu == 0x1000007:
            require(offset + size <= len(data), 'Invalid Mach-O slice bounds.')
            return offset
    raise ValueError('No x86_64 slice.')


def build_mso99(original, certificate):
    profile = binary_profile('mso99', original)
    require(digest(certificate) == CERT_HASH, 'Wrong certificate. Use prepare-donor.')
    offset, count, operand = profile['cert_offset'], 2352, profile['length_offset']
    require(original[operand - 1:operand + 4] == bytes.fromhex('be30090000'), 'Unexpected length instruction.')
    old = base64.b64decode(original[offset:offset + count * 2].decode('utf-16le'), validate=True)
    require(digest(old) == '8d4a3715e616b63369c9b1187240413248f00b452464b5e63ad3cc8cccb502e0', 'Unexpected old CA.')
    encoded = base64.b64encode(certificate)
    require(len(encoded) == 2284, 'Unexpected certificate size.')
    result = bytearray(original)
    result[offset:offset + count * 2] = encoded.decode('ascii').encode('utf-16le') + bytes((count - len(encoded)) * 2)
    result[operand:operand + 4] = struct.pack('<I', len(encoded))
    require(digest(result) == profile['patched']['mso99'], 'Unexpected mso99 output.')
    return bytes(result)


def build_mso30(original):
    profile = binary_profile('mso30', original)
    offset = x86_offset(original)
    require(offset == 0x4000, 'Unexpected slice offset.')
    thin = original[offset:]
    cave, start, end = 0x3000, profile['header_start'], profile['header_end']
    literal = '16.83\0'.encode('utf-16le')
    require(32 + struct.unpack_from('<I', thin, 20)[0] < cave, 'Padding overlaps load commands.')
    require(thin[cave:cave + len(literal)] == bytes(len(literal)), 'Padding is not empty.')
    expected = bytes.fromhex(profile['expected'])
    require(thin[start:end] == expected, 'Unexpected header-building instructions.')
    patch = bytes.fromhex('488dbdd8f9ffff')
    patch += bytes.fromhex('488d35') + struct.pack('<i', cave - (start + len(patch) + 7))
    patch += b'\xe8' + struct.pack('<i', profile['constructor'] - (start + len(patch) + 5))
    patch += b'\x90' * (end - start - len(patch))
    result = bytearray(original)
    result[offset + start:offset + end] = patch
    result[offset + cave:offset + cave + len(literal)] = literal
    require(digest(result) == profile['patched']['mso30'], 'Unexpected mso30 output.')
    return bytes(result)


def prepare(args):
    mac_only()
    work = args.work_dir.expanduser().resolve()
    work.mkdir(parents=True, exist_ok=True)
    certificate = work / 'office-licensing-ca-2023.der'
    if certificate.exists():
        require(file_hash(certificate) == CERT_HASH, 'Existing certificate has wrong hash; use another work directory.')
        print('Verified existing public CA:', certificate)
        return
    require(bool(args.package) != bool(args.download), 'Choose exactly one of --package or --download.')
    package = args.package.expanduser().resolve() if args.package else work / 'Word16.83.pkg'
    if args.download and not package.exists():
        partial = work / 'Word16.83.pkg.partial'
        require(not partial.exists(), 'Partial download exists; remove it or use another work directory.')
        try:
            run(['/usr/bin/curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https', '--output', partial, PACKAGE_URL])
            require(file_hash(partial) == PACKAGE_HASH, 'Microsoft package hash mismatch; refusing extraction.')
            partial.rename(package)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
    require(file_hash(package) == PACKAGE_HASH, 'Package hash mismatch; only the documented 16.83 package is accepted.')
    # The pinned digest binds the package to the signed/notarized package verified during research.
    with tempfile.TemporaryDirectory(prefix='office-donor-', dir=str(work)) as tmp:
        expanded = Path(tmp) / 'expanded'
        run(['/usr/sbin/pkgutil', '--expand-full', package, expanded])
        donors = list(expanded.glob('**/Microsoft Word.app/Contents/Frameworks/mso99.framework/Versions/A/mso99'))
        require(len(donors) == 1, 'Expected exactly one donor mso99.')
        data = donors[0].read_bytes()
        require(digest(data) == DONOR_HASH, 'Donor framework hash mismatch.')
        cert = base64.b64decode(data[0x1d0ae70:0x1d0ae70 + 2284 * 2].decode('utf-16le'), validate=True)
        require(digest(cert) == CERT_HASH, 'Extracted CA hash mismatch.')
        certificate.write_bytes(cert)
    print('Verified public CA:', certificate)


def inspect(args):
    data = originals(args.source.expanduser().resolve())
    print('Supported original framework hashes found (x86_64 patch only).')
    print(json.dumps({n: digest(b) for n, b in data.items()}, indent=2))
    print('Read-only inspection complete. No files changed.')


def apply(args):
    mac_only()
    require(platform.machine() == 'x86_64', 'Apply on an Intel Mac; ARM64 is not supported.')
    require(os.geteuid() != 0, 'Run as your normal user, without sudo.')
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().absolute()
    require(not output.exists() and not output.is_symlink(), 'Output exists; choose a new output directory.')
    require(source not in output.resolve().parents, 'Output cannot be inside the source app.')
    data = originals(source)
    require(all(digest(data[n]) == ORIGINAL[n] for n in ORIGINAL), 'Copy mode supports Word 16.66.1; use suite.py for other supported builds.')
    cert = args.certificate.expanduser().read_bytes()
    patched = {'mso99': build_mso99(data['mso99'], cert), 'mso30': build_mso30(data['mso30'])}
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', source])
    source_main_hash = file_hash(source / 'Contents/MacOS/Microsoft Word')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.office-backport-', dir=str(output.parent)))
    try:
        app = staging / 'Microsoft Word.app'
        run(['/usr/bin/ditto', source, app])
        # Validate the copied inputs too, detecting source changes during copy.
        originals(app)
        require(file_hash(app / 'Contents/MacOS/Microsoft Word') == source_main_hash, 'Executable changed during copying.')
        backups = staging / 'original-framework-binaries'
        backups.mkdir()
        for name, payload in patched.items():
            (backups / name).write_bytes(data[name])
            target = app / REL[name]
            target.write_bytes(payload)
            framework = app / 'Contents/Frameworks' / (name + '.framework')
            run(['/usr/bin/codesign', '--force', '--sign', '-', framework])
            run(['/usr/bin/codesign', '--verify', '--strict', framework])
        require(file_hash(app / 'Contents/MacOS/Microsoft Word') == source_main_hash, 'Main executable changed.')
        originals(source)
        receipt = {'patcher_version': VERSION, 'supported_word_build': '16.66.22101101',
                   'source': str(source), 'main_executable_sha256': source_main_hash,
                   'original_sha256': ORIGINAL, 'pre_signing_sha256': PATCHED,
                   'installed_sha256': {n: file_hash(app / rel) for n, rel in REL.items()},
                   'activation_tested_by_this_run': False,
                   'note': 'Frameworks are ad hoc signed. Outer app resource seal is not a valid Microsoft seal. Original app is untouched.'}
        (staging / 'patch-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        require(not output.exists(), 'Output appeared during processing; refusing to replace it.')
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print('Created test copy:', output / 'Microsoft Word.app')
    print('Quit other Word instances, then open this exact copy and activate normally.')
    print('Original app unchanged. See README for rollback and limitations.')


def verify(args):
    mac_only()
    output = args.output.expanduser().resolve()
    receipt = json.loads((output / 'patch-receipt.json').read_text())
    app = output / 'Microsoft Word.app'
    require(receipt['patcher_version'] == VERSION, 'Unknown receipt version.')
    for n, rel in REL.items():
        require(file_hash(app / rel) == receipt['installed_sha256'][n], n + ' changed since patching.')
        require(file_hash(output / 'original-framework-binaries' / n) == ORIGINAL[n], n + ' backup differs.')
        run(['/usr/bin/codesign', '--verify', '--strict', app / 'Contents/Frameworks' / (n + '.framework')])
    require(file_hash(app / 'Contents/MacOS/Microsoft Word') == receipt['main_executable_sha256'], 'Main executable changed.')
    print('Files match this local receipt; both framework signatures verify.')
    print('This checks local consistency, not publisher authenticity or successful activation.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('inspect', help='Read-only exact-build check')
    p.add_argument('--source', type=Path, default=Path('/Applications/Microsoft Word.app'))
    p.set_defaults(func=inspect)
    p = sub.add_parser('prepare-donor', help='Extract only the public CA from the pinned Microsoft package')
    p.add_argument('--work-dir', required=True, type=Path)
    p.add_argument('--package', type=Path)
    p.add_argument('--download', action='store_true')
    p.set_defaults(func=prepare)
    p = sub.add_parser('apply', help='Create and patch a separate test copy; never patch in place')
    p.add_argument('--source', type=Path, default=Path('/Applications/Microsoft Word.app'))
    p.add_argument('--certificate', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.set_defaults(func=apply)
    p = sub.add_parser('verify', help='Verify files against the generated local receipt')
    p.add_argument('--output', required=True, type=Path)
    p.set_defaults(func=verify)
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)

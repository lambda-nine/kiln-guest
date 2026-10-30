#!/usr/bin/env python3
"""Exact guest source stages and fresh, verified Cargo sources.

Standard library only. The wrapper sends this file to the VM as `python3 -I -c`,
so it cannot depend on its own path or sibling modules. The wrapper also imports
it under the host's python3, so tomllib loads only where Cargo.lock is parsed.
"""
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess as sp
import sys
import tarfile
import tempfile

MANIFEST = '.source-manifest.json'
EXCLUDED = {'.git', '__pycache__', 'dist', 'results'}
SCHEMA = 1
MAX_MANIFEST_BYTES = 16*1024*1024
SHA256 = re.compile(r'[0-9a-f]{64}')
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
CRATE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]*')
CRATE_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?')
AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for data in iter(lambda: f.read(1024*1024), b''): h.update(data)
    return h.hexdigest()

def _open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    f = os.fdopen(fd, 'rb')
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        f.close()
        raise ValueError(f'not a regular file: {path}')
    return f

def _scan(root):
    """Walk source paths without following links; exclusions apply at any level."""
    files, directories = [], []
    def visit(relative):
        with os.scandir(Path(root)/relative) as entries: found = list(entries)
        for entry in found:
            path = f'{relative}/{entry.name}' if relative else entry.name
            if entry.name in EXCLUDED or path == MANIFEST: continue
            path.encode('utf-8')
            if entry.is_symlink(): raise ValueError(f'symlink in source: {path}')
            if entry.is_dir(follow_symlinks=False):
                directories.append(path); visit(path)
            elif entry.is_file(follow_symlinks=False): files.append(path)
            else: raise ValueError(f'special file in source: {path}')
    visit('')
    return sorted(files), sorted(directories)

def _record(root, path):
    h = hashlib.sha256(); size = 0
    with _open_regular(Path(root)/path) as f:
        mode = stat.S_IMODE(os.fstat(f.fileno()).st_mode)
        for data in iter(lambda: f.read(1024*1024), b''):
            h.update(data); size += len(data)
    if mode & ~0o777: raise ValueError(f'setuid, setgid or sticky source file: {path}')
    return {'path': path, 'mode': mode, 'size': size, 'sha256': h.hexdigest()}

def source_inventory(root):
    return {'schema': SCHEMA, 'files': [_record(root, path) for path in _scan(root)[0]]}

def inventory_digest(inventory):
    text = json.dumps(inventory, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(text.encode()).hexdigest()

def _check_path(path):
    parts = path.split('/') if isinstance(path, str) else []
    if not parts or any(part in ('', '.', '..') for part in parts) or '\0' in path:
        raise ValueError(f'unsafe source path: {path!r}')
    if path == MANIFEST or EXCLUDED.intersection(parts):
        raise ValueError(f'excluded source path: {path!r}')

def _check_inventory(inventory):
    if not isinstance(inventory, dict) or set(inventory) != {'schema', 'files'} \
            or inventory['schema'] != SCHEMA or not isinstance(inventory['files'], list):
        raise ValueError('malformed source manifest')
    paths = []
    for record in inventory['files']:
        if not isinstance(record, dict) or set(record) != {'path', 'mode', 'size', 'sha256'}:
            raise ValueError('malformed source manifest record')
        _check_path(record['path'])
        mode, size, digest = record['mode'], record['size'], record['sha256']
        if type(mode) is not int or not 0 <= mode <= 0o777 or type(size) is not int or size < 0 \
                or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError(f'malformed source manifest record: {record["path"]}')
        paths.append(record['path'])
    if paths != sorted(set(paths)): raise ValueError('source manifest paths not sorted and unique')

def verify_source(root):
    """Prove a stage holds exactly its inventory; return the inventory and digest."""
    with _open_regular(Path(root)/MANIFEST) as f: expected = json.loads(f.read())
    _check_inventory(expected)
    files, directories = _scan(root)
    want = {record['path']: record for record in expected['files']}
    have = {record['path']: record for record in (_record(root, path) for path in files)}
    needed = {'/'.join(path.split('/')[:i]) for path in want for i in range(1, path.count('/')+1)}
    errors = [f'missing {path}' for path in sorted(set(want)-set(have))]
    errors += [f'extra {path}' for path in sorted(set(have)-set(want))]
    errors += [f'extra directory {path}' for path in sorted(set(directories)-needed)]
    errors += [f'altered {path}' for path in sorted(set(want) & set(have)) if want[path] != have[path]]
    if errors: raise ValueError('source inventory: ' + '; '.join(errors))
    return {'digest': inventory_digest(expected), 'files': expected['files']}

def _tarinfo(path, size, mode):
    info = tarfile.TarInfo(path)
    info.size, info.mode = size, mode
    return info

def write_archive(root, stream, inventory=None):
    """Stream the inventory, then its files, with no host ownership or times."""
    inventory = inventory or source_inventory(root)
    data = (json.dumps(inventory, sort_keys=True, indent=1) + '\n').encode()
    with tarfile.open(fileobj=stream, mode='w|', format=tarfile.PAX_FORMAT) as tar:
        tar.addfile(_tarinfo(MANIFEST, len(data), 0o644), io.BytesIO(data))
        for record in inventory['files']:
            with _open_regular(Path(root)/record['path']) as f:
                tar.addfile(_tarinfo(record['path'], record['size'], record['mode']), f)
    return inventory_digest(inventory)

def _make_directories(base, parts):
    current = Path(base)
    for part in parts:
        current = current/part
        try:
            os.mkdir(current); os.chmod(current, 0o755)
        except FileExistsError:
            if not stat.S_ISDIR(os.lstat(current).st_mode):
                raise ValueError(f'path conflict: {current}') from None

def _write_new(base, relative, source, size, mode):
    """Create one file that cannot already exist and return its SHA-256."""
    parts = relative.split('/')
    _make_directories(base, parts[:-1])
    try: fd = os.open(Path(base)/relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError: raise ValueError(f'duplicate path: {relative}') from None
    h = hashlib.sha256(); left = size
    with os.fdopen(fd, 'wb') as f:
        while left:
            data = source.read(min(left, 1024*1024))
            if not data: raise ValueError(f'truncated file: {relative}')
            f.write(data); h.update(data); left -= len(data)
        os.fchmod(f.fileno(), mode)
    return h.hexdigest()

def _extract_source(stream, directory, expected_digest):
    expected = None
    try:
        with tarfile.open(fileobj=stream, mode='r|') as tar:
            for member in tar:
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    raise ValueError(f'non-regular archive member: {member.name}')
                if expected is None:
                    if member.name != MANIFEST or member.size > MAX_MANIFEST_BYTES:
                        raise ValueError(f'archive must begin with {MANIFEST}')
                    data = tar.extractfile(member).read()
                    inventory = json.loads(data)
                    _check_inventory(inventory)
                    if expected_digest and inventory_digest(inventory) != expected_digest:
                        raise ValueError('source manifest differs from the expected digest')
                    expected = {record['path']: record for record in inventory['files']}
                    _write_new(directory, MANIFEST, io.BytesIO(data), len(data), 0o644)
                    continue
                # Only paths the validated inventory names, and each only once, get past here.
                record = expected.pop(member.name, None)
                if record is None: raise ValueError(f'unexpected archive member: {member.name}')
                if member.size != record['size'] or stat.S_IMODE(member.mode) != record['mode']:
                    raise ValueError(f'archive member differs from inventory: {member.name}')
                digest = _write_new(directory, member.name, tar.extractfile(member), member.size, record['mode'])
                if digest != record['sha256']:
                    raise ValueError(f'archive member digest mismatch: {member.name}')
    except tarfile.TarError as error:
        raise ValueError(f'malformed source archive: {error}') from error
    if expected is None: raise ValueError(f'archive has no {MANIFEST}')
    if expected: raise ValueError('archive omits: ' + ', '.join(sorted(expected)))
    while stream.read(1024*1024): pass
    return verify_source(directory)

def _renameat2(source, destination, flags):
    if not sys.platform.startswith('linux'):
        raise OSError(errno.ENOSYS, 'renameat2 requires Linux', str(destination))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if libc.renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(destination), flags):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))

def rename_exchange(source, destination): _renameat2(source, destination, RENAME_EXCHANGE)

def rename_noreplace(source, destination):
    if sys.platform.startswith('linux'): _renameat2(source, destination, RENAME_NOREPLACE)
    elif os.path.lexists(destination): raise FileExistsError(errno.EEXIST, 'exists', str(destination))
    else: os.rename(source, destination)

def _in_sibling(destination, populate, publish):
    """Fill an empty sibling and publish it. Whatever remains there is then deleted:
    a failed output, or the old tree after an exchange."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f'.{destination.name}.tmp-', dir=destination.parent))
    try:
        os.chmod(temporary, 0o755)
        result = populate(temporary)
        publish(temporary, destination)
        return result
    finally:
        if os.path.lexists(temporary): shutil.rmtree(temporary)

def stage_archive(stream, destination, expected_digest=None, exchange=rename_exchange):
    """Replace destination with exactly the archive's inventory, or leave it untouched."""
    destination = Path(os.path.abspath(destination))
    def publish(temporary, final):
        if os.path.lexists(final): exchange(temporary, final)
        else: os.replace(temporary, final)
    if os.path.lexists(destination) and not stat.S_ISDIR(os.lstat(destination).st_mode):
        raise ValueError(f'stage destination is not a directory: {destination}')
    return _in_sibling(destination, lambda d: _extract_source(stream, d, expected_digest), publish)

def publish_new_directory(final, populate, publish=rename_noreplace):
    """Publish a directory only on success; refuse before populate if final exists."""
    final = Path(os.path.abspath(final))
    if os.path.lexists(final): raise ValueError(f'refusing to overwrite {final}')
    return _in_sibling(final, populate, publish)

def parse_cargo_lock(text):
    """Return registry and local packages; anything else in the lock is refused."""
    import tomllib
    lock = tomllib.loads(text)
    if set(lock) != {'version', 'package'} or lock['version'] not in (3, 4):
        raise ValueError('unsupported Cargo.lock format')
    registry, local, seen = [], [], set()
    for package in lock['package']:
        if not set(package) <= {'name', 'version', 'source', 'checksum', 'dependencies'}:
            raise ValueError(f'unsupported Cargo.lock package: {package}')
        name, version = package.get('name'), package.get('version')
        if not isinstance(name, str) or not CRATE_NAME.fullmatch(name) \
                or not isinstance(version, str) or not CRATE_VERSION.fullmatch(version):
            raise ValueError(f'unsafe Cargo.lock package: {package}')
        if (name, version) in seen: raise ValueError(f'duplicate Cargo.lock package: {name} {version}')
        seen.add((name, version))
        if 'source' not in package:
            if 'checksum' in package: raise ValueError(f'local package has a checksum: {name}')
            local.append({'name': name, 'version': version})
            continue
        if package['source'] != REGISTRY:
            raise ValueError(f'unsupported Cargo source for {name}: {package["source"]}')
        checksum = package.get('checksum')
        if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
            raise ValueError(f'registry package lacks a SHA-256 checksum: {name} {version}')
        registry.append({'name': name, 'version': version, 'source': REGISTRY, 'sha256': checksum})
    key = lambda package: (package['name'], package['version'])
    return sorted(registry, key=key), sorted(local, key=key)

def download_crate(url, path):
    sp.run(['curl', '-q', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
            '-fLsS', '--retry', '2', url, '-o', str(path)], check=True)

def _crate_bytes(package, directory, fetcher):
    """Read the compressed crate into memory, so what is hashed is what is extracted."""
    name, version, digest = package['name'], package['version'], package['sha256']
    path = directory/f'{name}-{version}.crate'
    if not os.path.lexists(path):
        fd, partial = tempfile.mkstemp(prefix=path.name+'.', suffix='.partial', dir=directory)
        os.close(fd)
        try:
            fetcher(f'https://static.crates.io/crates/{name}/{name}-{version}.crate', partial)
            if sha(partial) != digest: raise ValueError(f'download checksum mismatch: {name} {version}')
            os.chmod(partial, 0o644); os.replace(partial, path)
        finally:
            if os.path.lexists(partial): os.unlink(partial)
    with _open_regular(path) as f: data = f.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f'crate checksum mismatch, refusing to extract: {path}')
    return data

def _extract_crate(data, package, vendor):
    top = f"{package['name']}-{package['version']}"
    destination = vendor/top
    destination.mkdir()
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for member in tar:
            parts = member.name.split('/')
            if parts[0] != top or any(part in ('', '.', '..') or '\\' in part for part in parts):
                raise ValueError(f'unsafe path in {top}: {member.name}')
            member.name.encode('utf-8')
            relative = '/'.join(parts[1:])
            if member.isdir(): _make_directories(destination, parts[1:])
            elif member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not relative:
                raise ValueError(f'non-regular member in {top}: {member.name}')
            else:
                mode = 0o755 if member.mode & 0o100 else 0o644
                hashes[relative] = _write_new(destination, relative, tar.extractfile(member), member.size, mode)
    if 'Cargo.toml' not in hashes: raise ValueError(f'{top} has no Cargo.toml')
    checksum = json.dumps({'files': hashes, 'package': package['sha256']}, sort_keys=True).encode()
    _write_new(destination, '.cargo-checksum.json', io.BytesIO(checksum), len(checksum), 0o644)

def _refuse_cargo_config(start):
    """Cargo merges config from every ancestor of its working directory, CARGO_HOME or not."""
    for directory in [start, *start.parents]:
        for name in ['config', 'config.toml']:
            if os.path.lexists(directory/'.cargo'/name):
                raise ValueError(f'Cargo config would influence the build: {directory/".cargo"/name}')

def vendor_crates(kiln_source, cache, work, fetcher=download_crate):
    """Extract Cargo.lock's crates into new work/vendor and work/cargo-home trees.
    Only compressed crates are cached, and each is rehashed before each extraction."""
    kiln_source, cache, work = Path(kiln_source), Path(cache), Path(work)
    _refuse_cargo_config(kiln_source.resolve())
    with _open_regular(kiln_source/'Cargo.lock') as f: lock = f.read()
    registry, local = parse_cargo_lock(lock.decode())
    crates = cache/'crates'; crates.mkdir(parents=True, exist_ok=True)
    (work/'cargo-home').mkdir(parents=True)
    vendor = work/'vendor'; vendor.mkdir()
    for package in registry:
        _extract_crate(_crate_bytes(package, crates, fetcher), package, vendor)
    return {'cargo_lock_sha256': hashlib.sha256(lock).hexdigest(),
            'registry_packages': registry, 'local_packages': local}

def cargo_arguments(vendor):
    """Offline, lock-exact Cargo against the verified vendor tree only."""
    return ['--frozen', '--config', 'source.crates-io.replace-with="verified-vendor"',
            '--config', f'source.verified-vendor.directory={json.dumps(str(vendor))}']

def cargo_environment(environ, work):
    """Drop inherited wrappers, flags and homes; the toolchain comes from the pinned PATH."""
    env = {key: value for key, value in environ.items() if not key.startswith(('CARGO', 'RUST'))}
    env['CARGO_HOME'] = str(Path(work)/'cargo-home')
    return env

if __name__ == '__main__':
    for number in [signal.SIGTERM, signal.SIGHUP]: signal.signal(number, lambda *_: sys.exit(143))
    if len(sys.argv) != 4 or sys.argv[1] != 'stage': sys.exit('usage: inputs.py stage DESTINATION DIGEST')
    print(json.dumps({'stage': sys.argv[2], 'digest': stage_archive(sys.stdin.buffer, sys.argv[2], sys.argv[3])['digest']}))

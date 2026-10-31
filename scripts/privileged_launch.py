"""Root-only staging and descriptor-bound privileged execution (Linux)."""
import errno
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from phase1b_contract import verify_static_elf

TRUST_ROOT = Path('/var/lib/kiln-guest-launch')

def _trusted(info, directory):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if info.st_uid != 0 or info.st_mode & 0o022 or not kind(info.st_mode):
        raise ValueError('launch path must be root-owned and not group/world writable')

def trusted_directory(path, create=False):
    """Walk from / with no symlinks; validate each opened component, not a stat path."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute launch path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _trusted(os.fstat(fd), True)
        for part in path.parts[1:]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            _trusted(os.fstat(fd), True)
        return fd
    except BaseException:
        os.close(fd)
        raise

def digest_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    for block in iter(lambda: os.read(fd, 1024*1024), b''): h.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return h.hexdigest()

def verified_open(path, digest):
    parent = trusted_directory(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally: os.close(parent)
    try:
        _trusted(os.fstat(fd), False)
        if digest_fd(fd) != digest: raise ValueError('VMM executable or staged artifact digest mismatch')
        return fd
    except BaseException:
        os.close(fd)
        raise

def atomic_copy(source, target, digest, executable=False):
    """Copy a stream to a private temporary inode, publish atomically, hash by fd."""
    parent = trusted_directory(Path(target).parent)
    os.close(parent)
    fd, temporary = tempfile.mkstemp(prefix='.install-', dir=Path(target).parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            for block in iter(lambda: source.read(1024*1024), b''): output.write(block)
            output.flush(); os.fchmod(output.fileno(), 0o555 if executable else 0o444)
            os.fsync(output.fileno())
        # Verify the completed copy both before publication and after installation.
        check = verified_open(temporary, digest); os.close(check)
        os.replace(temporary, target)
        check = verified_open(target, digest); os.close(check)
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)

def copy_artifact(source, target, record):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != record['bytes']:
            raise ValueError('invalid source artifact')
        atomic_copy(stream, target, record['sha256'])

# Phase 1b reference for the contract's executable identity rules (Linux root).
# B3 implements these in kilnd-helper; nothing here installs or launches a VMM.
AT_EMPTY_PATH = 0x1000
SYS_EXECVEAT = {'aarch64': 281, 'x86_64': 322}

def no_extended_acl(fd):
    """Fail closed: a present or unreadable ACL is not a permission we can reason about."""
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.getxattr(fd, name)
        except OSError as error:
            if error.errno == errno.ENODATA: continue
            raise ValueError('unsupported permission check') from error
        raise ValueError('extended or default ACL on a protected path')

def protected_directory(path, create=False):
    """trusted_directory plus ACLs on every component, from an opened /."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute protected path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _trusted(os.fstat(fd), True); no_extended_acl(fd)
        for part in path.parts[1:]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
            _trusted(os.fstat(fd), True); no_extended_acl(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise

def _check_installed(fd, pin):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o555 or info.st_nlink != 1:
        raise ValueError('installed executable must be root-owned 0555, regular and single-link')
    if info.st_size != pin['bytes']: raise ValueError('installed executable size mismatch')
    no_extended_acl(fd)
    try:
        os.getxattr(fd, 'security.capability')
    except OSError as error:
        if error.errno != errno.ENODATA: raise ValueError('unsupported permission check') from error
    else:
        raise ValueError('installed executable has file capabilities')
    if digest_fd(fd) != pin['sha256']: raise ValueError('installed executable digest mismatch')
    verify_static_elf(os.pread(fd, info.st_size, 0))
    return info

def open_executable(path, role, pin, generation):
    """Open one installed role and hash that FD. Returns (fd, journal identity tuple)."""
    path = Path(path)
    parent = protected_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
    finally: os.close(parent)
    try:
        info = _check_installed(fd, pin)
        return fd, {'role': role, 'st_dev': info.st_dev, 'st_ino': info.st_ino, 'bytes': info.st_size,
                    'sha256': pin['sha256'], 'installation_generation': generation}
    except BaseException:
        os.close(fd)
        raise

def install_executable(source_fd, store, role, pin):
    """Copy from an authenticated source FD into sha256/<digest>/<role>. Never repairs an object."""
    directory = Path(store)/'sha256'/pin['sha256']
    parent = protected_directory(directory, create=True)
    target = directory/role
    try:
        if os.path.lexists(target):
            os.close(open_executable(target, role, pin, 1)[0])
            return target
        fd, temporary = tempfile.mkstemp(prefix='.install-', dir=directory)
        try:
            os.lseek(source_fd, 0, os.SEEK_SET)
            for block in iter(lambda: os.read(source_fd, 1024*1024), b''): os.write(fd, block)
            os.fchmod(fd, 0o555); os.fsync(fd)
            _check_installed(fd, pin)
            os.link(temporary, target)  # Fails rather than replacing an existing digest object.
        finally:
            os.close(fd)
            os.unlink(temporary)
        os.fsync(parent)
        return target
    finally: os.close(parent)

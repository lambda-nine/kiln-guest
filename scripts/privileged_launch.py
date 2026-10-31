"""Root-only staging and descriptor-bound privileged execution (Linux)."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile

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

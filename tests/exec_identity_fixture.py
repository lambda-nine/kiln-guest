#!/usr/bin/env python3
"""Linux retained-FD replacement races: what actually ran, not what argv claimed.

Each executable role is installed into a protected store, opened and hashed, then
raced after verification and before exec while the launch child waits at a gate.
The parent then reads /proc/<pid>/exe through a pidfd-held process and compares
device, inode, size and FD-computed digest with the journal tuple. A pathname exec
is the negative control: it runs the replacement, and the contract must refuse it
even when bytes, digest and argv all match.

Real exec of real static ELF fixtures, not the jailer or VMM; B4 proves that chain.
Needs Linux root for root-owned store ancestors and the unprivileged attacker.

    sudo python3 -I tests/exec_identity_fixture.py OUTPUT.json
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'tests')]
from generate_phase1b_fixtures import FIXTURES, fixture_elf
import phase1b_contract as p1
from privileged_launch import (AT_EMPTY_PATH, SYS_EXECVEAT, TRUST_ROOT, digest_fd, install_executable,
                               open_executable, trusted_directory)

ATTACKER = 10001
RETAINED_FD_FLOOR = 100
CASES = ['source-parent', 'installed-name', 'installed-identical-bytes', 'installed-parent', 'closed-fd-reused']
libc = ctypes.CDLL(None, use_errno=True)


def strings(values):
    array = (ctypes.c_char_p * (len(values) + 1))()
    array[:len(values)] = [value.encode() for value in values]
    return array


def high_fd(fd):
    """Keep retained descriptors clear of the 3/4 handoff numbers, CLOEXEC."""
    moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, RETAINED_FD_FLOOR)
    os.close(fd)
    return moved


def control_socket():
    """Both ends clear of 3/4, so arranging the handoff FDs cannot overwrite either."""
    ours, theirs = socket.socketpair()
    try:
        return high_fd(os.dup(ours.fileno())), high_fd(os.dup(theirs.fileno()))
    finally:
        ours.close()
        theirs.close()


def spawn(argv, exec_fd=None, path=None, fds=None, gate_action=None):
    """Fork, arrange `fds` {target: (source, keep_on_exec)}, wait at a gate, then exec.

    `exec_fd` uses execveat(fd, "", ..., AT_EMPTY_PATH); `path` is the negative
    control. The race runs in `gate_action`, after fork and before exec.
    """
    gate_r, gate_w = map(high_fd, os.pipe())
    status_r, status_w = map(high_fd, os.pipe())
    argv_array, env_array = strings(argv), strings([])
    number = SYS_EXECVEAT[os.uname().machine]
    pid = os.fork()
    if pid == 0:
        try:
            null = os.open('/dev/null', os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(null, fd, inheritable=True)
            for target, (source, keep) in (fds or {}).items():
                os.dup2(source, target, inheritable=keep)
            os.read(gate_r, 1)
            if path is not None:
                os.execve(path, argv, {})
            libc.syscall(ctypes.c_long(number), ctypes.c_int(exec_fd), ctypes.c_char_p(b''),
                         argv_array, env_array, ctypes.c_int(AT_EMPTY_PATH))
            os.write(status_w, str(ctypes.get_errno()).encode())
        except OSError as error:
            os.write(status_w, str(error.errno).encode())
        finally:
            os._exit(127)
    os.close(gate_r)
    os.close(status_w)
    try:
        if gate_action:
            gate_action()
        try:
            os.write(gate_w, b'1')
        except BrokenPipeError:
            pass  # The child already failed; its status below names the reason.
        os.close(gate_w)
        failure = os.read(status_r, 16)
    except BaseException:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise
    finally:
        os.close(status_r)
    if failure:
        os.waitpid(pid, 0)
        raise OSError(int(failure), 'exec refused', argv[0])
    return pid


def observe(pid, role):
    """The actual tuple through the running process, plus its surviving descriptors."""
    pidfd = os.pidfd_open(pid)
    try:
        exe = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(exe)
            observed = {'role': role, 'st_dev': info.st_dev, 'st_ino': info.st_ino,
                        'bytes': info.st_size, 'sha256': digest_fd(exe)}
        finally:
            os.close(exe)
        fds = {}
        for name in os.listdir(f'/proc/{pid}/fd'):
            target = os.stat(f'/proc/{pid}/fd/{name}')
            fds[int(name)] = {'st_dev': target.st_dev, 'st_ino': target.st_ino, 'socket': stat.S_ISSOCK(target.st_mode)}
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]
        if select.select([pidfd], [], [], 0)[0]:
            raise ValueError('process exited during observation')
        return observed, fds, [item.decode() for item in argv]
    finally:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        os.close(pidfd)
        os.waitpid(pid, 0)


def as_attacker(function):
    """Run a filesystem attack in a child holding only the unprivileged test UID."""
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(ATTACKER)
            os.setuid(ATTACKER)
            function()
            os._exit(0)
        except OSError as error:
            os._exit(1 if error.errno in (errno.EACCES, errno.EPERM) else 2)
        finally:
            os._exit(3)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


class Installation:
    """One role's approved source tree, protected store object and retained FD."""

    def __init__(self, role, pin, data):
        self.role, self.pin, self.data = role, pin, data
        fd = trusted_directory(TRUST_ROOT, create=True)
        os.close(fd)
        self.private = Path(tempfile.mkdtemp(prefix='b1-exec-', dir=TRUST_ROOT))
        self.cache = Path(tempfile.mkdtemp(prefix='b1-source-', dir='/var/tmp'))
        os.chown(self.cache, ATTACKER, ATTACKER)
        self.cache.chmod(0o775)
        self.source = self.cache/'release'/role
        self.source.parent.mkdir()
        os.chown(self.source.parent, ATTACKER, ATTACKER)
        self.source.write_bytes(data)
        self.source.chmod(0o755)
        source_fd = os.open(self.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if digest_fd(source_fd) != pin['sha256']:
            raise ValueError('source differs from pin')
        self.store = self.private/'exec'
        self.installed = install_executable(source_fd, self.store, role, pin)
        os.close(source_fd)
        fd, self.expected = open_executable(self.installed, role, pin, 1)
        self.fd = high_fd(fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
        shutil.rmtree(self.private)
        shutil.rmtree(self.cache)

    def replace_installed(self, data):
        """Test-only root fault injection, stronger than the unprivileged threat."""
        temporary = self.installed.with_name('.fault-injection')
        temporary.write_bytes(data)
        temporary.chmod(0o555)
        os.replace(temporary, self.installed)

    def replace_source_parent(self):
        def attack():
            parent = self.source.parent
            parent.rename(parent.with_name('approved-release'))
            parent.mkdir()
            self.source.write_bytes(fixture_elf(self.role + '-attacker'))
            self.source.chmod(0o755)
        return as_attacker(attack)

    def swap_installed_parent(self):
        """Root renames the digest directory and plants another object under the old name."""
        parent = self.installed.parent
        parent.rename(parent.with_name(parent.name + '-old'))
        parent.mkdir(mode=0o700)
        self.installed.write_bytes(self.data)
        self.installed.chmod(0o555)


def launch(install, argv):
    """Exec through the retained FD using this role's frozen boundary."""
    if install.role == 'jailer':
        # S to J: V and control on 3/4 survive; J's own exec FD stays >=5 and CLOEXEC.
        vmm = open_store_peer(install)
        ours, theirs = control_socket()
        try:
            pid = spawn(argv, exec_fd=install.fd, fds={3: (vmm['fd'], True), 4: (theirs, True)},
                        gate_action=install.race)
            return pid, 'before-S-exec-J', vmm
        finally:
            os.close(ours)
            os.close(theirs)
    if install.role == 'firecracker':
        # J to V: FD 3 is this role and 3/4 are CLOEXEC, so neither reaches the VMM.
        ours, theirs = control_socket()
        try:
            pid = spawn(argv, exec_fd=3, fds={3: (install.fd, False), 4: (theirs, False)},
                        gate_action=install.race)
            return pid, 'before-J-exec-V', None
        finally:
            os.close(ours)
            os.close(theirs)
    boundary = 'before-formatter-exec' if install.role == 'mkfs.xfs' else 'before-worker-exec'
    return spawn(argv, exec_fd=install.fd, gate_action=install.race), boundary, None


def open_store_peer(install):
    """A verified VMM descriptor for the S-to-J handoff, in this installation's own store."""
    data = (FIXTURES/'executables/firecracker').read_bytes()
    pin = {'bytes': len(data), 'sha256': p1.digest(data)}
    source = install.private/'peer-source'
    source.write_bytes(data)
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    path = install_executable(source_fd, install.store, 'firecracker', pin)
    os.close(source_fd)
    fd, identity = open_executable(path, 'firecracker', pin, 1)
    moved = high_fd(fd)
    install.peer_fd = moved
    return {'fd': moved, 'identity': identity}


def rejected(function, *args):
    try:
        function(*args)
    except ValueError as error:
        return str(error)
    return None


def identity_fds_ok(role, fds, peer):
    """Exactly the descriptors the handoff recipe allows, identified by inode for J's FD 3."""
    if role == 'jailer':
        return (sorted(fds) == [0, 1, 2, 3, 4] and fds[3]['st_ino'] == peer['identity']['st_ino']
                and fds[3]['st_dev'] == peer['identity']['st_dev'] and fds[4]['socket'])
    return sorted(fds) == [0, 1, 2]


def run_case(role, pin, data, argv, case):
    install = Installation(role, pin, data)
    install.peer_fd = None
    record = {'role': role, 'race': case, 'expected': install.expected, 'argv': argv}
    try:
        if case == 'source-parent':
            install.race = lambda: record.update(attacker_source_parent_exit=install.replace_source_parent())
            control_path = install.source
        elif case == 'installed-name':
            install.race = lambda: install.replace_installed(fixture_elf(role + '-replacement'))
            control_path = install.installed
        elif case == 'installed-identical-bytes':
            install.race = lambda: install.replace_installed(data)
            control_path = install.installed
        elif case == 'installed-parent':
            install.race = install.swap_installed_parent
            control_path = install.installed
        elif case == 'closed-fd-reused':
            # Close the retained number and let another inode, same bytes, land on it.
            number = install.fd
            install.replace_installed(data)
            os.close(number)
            fresh = os.open(install.installed, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            os.dup2(fresh, number, inheritable=False)
            os.close(fresh)
            info = os.fstat(number)
            reused = {'role': role, 'st_dev': info.st_dev, 'st_ino': info.st_ino, 'bytes': info.st_size,
                      'sha256': digest_fd(number)}
            record['reused_fd_preexec_refusal'] = rejected(p1.verify_observation, install.expected, reused)
            if record['reused_fd_preexec_refusal'] is None:
                raise AssertionError('reused descriptor passed revalidation')
            # Negative control only: executing it must show the wrong tuple, never a pass.
            pid = spawn(argv, exec_fd=number)
            observed, _, _ = observe(pid, role)
            record['reused_fd_observed'] = observed
            record['reused_fd_observation_refusal'] = rejected(p1.verify_observation, install.expected, observed)
            record['digest_matches_prior_hash'] = observed['sha256'] == install.expected['sha256']
            record['verdict'] = 'refused'
            return record
        else:
            raise ValueError(case)
        pid, boundary, peer = launch(install, argv)
        observed, fds, actual_argv = observe(pid, role)
        p1.verify_observation(install.expected, observed)
        record.update(boundary=boundary, observed=observed, surviving_fds=sorted(fds), actual_argv=actual_argv,
                      retained_fd_ran_expected_inode=True, handoff_fds_exact=identity_fds_ok(role, fds, peer))
        # Negative control: the same argv through the pathname runs the replacement.
        pid = spawn(argv, path=str(control_path))
        control, _, control_argv = observe(pid, role)
        record.update(control_observed=control, control_argv_matches=control_argv == argv,
                      control_digest_matches_prior_hash=control['sha256'] == install.expected['sha256'],
                      control_refusal=rejected(p1.verify_observation, install.expected, control))
        record['protected_reopen_refusal'] = reopen_refusal(install)
        record['verdict'] = 'retained-inode-ran'
        return record
    finally:
        if install.peer_fd is not None:
            os.close(install.peer_fd)
        install.close()


def reopen_refusal(install):
    """Helper restart: a replaced installation must not satisfy the old plan."""
    try:
        fd, reopened = open_executable(install.installed, install.role, install.pin, 1)
    except ValueError as error:
        return str(error)
    os.close(fd)
    return rejected(p1.verify_reopen, install.expected, reopened)


def protected_rename_attempts(role, pin, data):
    """Every protected ancestor is rename-proof for the unprivileged UID."""
    install = Installation(role, pin, data)
    try:
        results = {}
        for path in [install.installed, install.installed.parent, install.store, install.private, TRUST_ROOT]:
            results[str(path.relative_to(TRUST_ROOT.parent))] = as_attacker(
                lambda path=path: os.rename(path, str(path) + '-swapped'))
        return results
    finally:
        install.close()


def run_all():
    plan = json.loads((FIXTURES/'plan.json').read_text())
    manifest = json.loads((FIXTURES/'bundle/manifest.json').read_text())
    launch_argv = {'jailer': plan['launch']['jailer_argv'], 'firecracker': plan['launch']['vmm_argv_semantic'],
                   'mkfs.xfs': plan['launch']['formatter_argv'], 'kilnd-helper': ['kilnd-helper']}
    records, renames = [], {}
    for role in p1.ROLES:
        data = (FIXTURES/'executables'/role).read_bytes()
        pin = manifest['executables'][role]
        renames[role] = protected_rename_attempts(role, pin, data)
        for case in CASES:
            records.append(run_case(role, pin, data, launch_argv[role], case))
    return {'kernel': os.uname().release, 'machine': os.uname().machine,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'fixture': 'real static aarch64 ELF test images; not the jailer or VMM; B4 proves the actual J/V chain',
            'records': records, 'unprivileged_rename_exit_codes': renames}


if __name__ == '__main__':
    result = run_all()
    Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(f"{len(result['records'])} races recorded")

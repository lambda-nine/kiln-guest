"""Schema 2 manifest, launch plan and identity contract for offline-768-v1 (B1).

Canonical JSON: ASCII bytes, Unicode-scalar key order, compact separators, Python
ensure_ascii escapes (lowercase hex, surrogate pairs), no normalization, root depth
0 and key/value depth +1 capped at 32; strict UTF-8 input at most 4 MiB, no BOM or
duplicate decoded keys. Integers only in [-2**63, 2**64-1], no negative zero,
leading zeros, plus signs, floats, exponents or non-finite constants.

This freezes the wire and fixture contract only: no allocation, installer,
broker or VM launcher. Schema 1 remains the legacy benchmark contract in
launch_contract.py. Passing here is never deployment approval: production is
refused until the broker, patched jailer and approved bundle exist, and B3
implements the privileged preflight this module does not perform.
"""
import copy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'offline-768-v1'
BUILD_REFUSAL = 'offline-768-v1 is unavailable until its reviewed artifacts exist: '
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024 * 1024
U64 = 2**64 - 1
ROLES = ('jailer', 'firecracker', 'mkfs.xfs', 'kilnd-helper')
ARTIFACTS = ('Image', 'kernel.config', 'kiln', 'rootfs.squashfs', 'kilnd-guest-broker')
ID128 = re.compile(r'[0-9a-f]{32}')
DIGEST = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')
SANDBOX_ID = re.compile(r'sb-[0-9a-f]{16}')
PLACEHOLDER = re.compile(r'\$([a-z_.]+)')
TIMING = {'--start-time-us', '--start-time-cpu-us', '--parent-cpu-time-us'}


def canonical(value):
    _bounded(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _bounded(value, depth=0):
    if depth > 32:
        raise ValueError('JSON depth')
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        integer(value, -(2**63), U64)
    elif isinstance(value, str):
        value.encode('utf-8')  # A lone surrogate escape is not strict UTF-8.
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError('JSON key must be a string')
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1)
    else:
        raise ValueError('only JSON integers, never floats')


def strict_json(raw):
    """Strict UTF-8 JSON: no BOM, duplicate keys, floats or non-finite constants."""
    if len(raw) > MAX_MANIFEST:
        raise ValueError('JSON exceeds 4 MiB')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def no_number(_):
        raise ValueError('floats/constants forbidden')
    def parse_integer(text):
        if text == '-0':
            raise ValueError('negative zero forbidden')
        return integer(int(text), -(2**63), U64)
    try:
        value = json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=pairs,
                           parse_int=parse_integer, parse_float=no_number, parse_constant=no_number)
        _bounded(value)
        return value
    except (RecursionError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid JSON') from error


def keys(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('missing/unknown fields')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('integer type/range')
    return value


def matching(value, pattern):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError('invalid identity string')
    return value


def _file_digest(relative):
    return digest((ROOT / relative).read_bytes())


@lru_cache(maxsize=1)
def _repository_digests():
    """Bundle input pins. toolchain-files.json is large; hash it once per process."""
    return {'phase1b_inputs_sha256': _file_digest('config/phase1b-inputs.json'),
            'pins_sha256': _file_digest('config/pins.json'),
            'build_lock_sha256': _file_digest('config/build-lock.json'),
            'toolchain_files_sha256': _file_digest('config/toolchain-files.json'),
            'init_source_sha256': _file_digest('src/init.c'),
            'security_policy_sha256': _file_digest('config/security-policy.json')}


def inputs_pin():
    return strict_json((ROOT / 'config/phase1b-inputs.json').read_bytes())


def contract():
    raw = (ROOT / 'config/phase1b-contract.json').read_bytes()
    pins = inputs_pin()
    if digest(raw) != pins['contract_sha256']:
        raise ValueError('contract recipe pin mismatch')
    policy = strict_json(raw)
    if digest(canonical(policy['handoff'])) != pins['handoff_recipe_sha256']:
        raise ValueError('handoff recipe pin mismatch')
    return policy


def verify_contract(value):
    if canonical(value) != canonical(contract()):
        raise ValueError('unsupported Phase 1b contract')


def refuse_build():
    """Keep bundle production closed while reviewed inputs are absent."""
    pins = inputs_pin()
    if pins['production_enabled'] is not False or not pins['missing_artifacts']:
        raise ValueError('production enablement requires a reviewed contract revision')
    raise ValueError(BUILD_REFUSAL + ', '.join(pins['missing_artifacts']))


def manifest_fields(policy):
    """Every schema 2 field fixed by this contract revision, other than bytes and digests."""
    pins = json.loads((ROOT / 'config/pins.json').read_text())
    return {'schema': policy['manifest_schema'], 'bundle_version': '0.2.0',
            'architecture': policy['architecture'],
            'kernel_version': pins['kernel']['version'] + '-kiln-guest1',
            'kiln_commit': pins['kiln_commit'],
            'firecracker_version': policy['firecracker_lineage'],
            'source_date_epoch': pins['source_date_epoch'],
            'broker': {'enabled': True, 'protocol': policy['broker']['protocol'],
                       'artifact': 'kilnd-guest-broker',
                       'lifecycle': 'init-supervised-no-restart',
                       'capabilities': ['hello', 'initialize', 'probe', 'exec', 'cancel']},
            'launch_contract': policy,
            'work_disk': {'filesystem': 'xfs', 'mount_options': policy['work']['mount_options'],
                          'minimum_mib': policy['work']['minimum_bytes'] // (1024 * 1024)},
            'inner_images': {'alpine': {'version': pins['alpine']['version'],
                                        'archive_sha256': pins['alpine']['sha256'],
                                        'shift_base': pins['sandbox_id_base']}},
            'kernel_policy': {'config_artifact': 'kernel.config',
                              'security_policy_sha256': _repository_digests()['security_policy_sha256']}}


def manifest_inputs(policy):
    return {**_repository_digests(), 'contract_sha256': inputs_pin()['contract_sha256'],
            'handoff_recipe_sha256': digest(canonical(policy['handoff']))}


def verify_manifest(raw, approved_sha256):
    """Production entry point. No fixture override or test schema is accepted."""
    matching(approved_sha256, DIGEST)
    if digest(raw) != approved_sha256:
        raise ValueError('independent manifest approval mismatch')
    manifest = strict_json(raw)
    if not isinstance(manifest, dict):
        raise ValueError('manifest object required')
    if manifest.get('fixture_only') is not False or type(manifest.get('schema')) is not int or manifest['schema'] != 2:
        raise ValueError('production disabled: fixture/legacy no-vsock is refused')
    # No production manifest exists at B1. B4/B5/B7 must revise this gate.
    raise ValueError('production disabled: broker/patched-jailer/bundle approval absent')


def _open_regular(directory_fd, name, limit):
    """Descriptor-relative open of one fixed name: regular, single link, within its cap."""
    if '/' in name or name in ('', '.', '..'):
        raise ValueError('unsafe artifact name')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f'{name}: not a single-link regular file')
        if info.st_size > limit:
            raise ValueError(f'{name}: exceeds size limit')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_fd(fd):
    return b''.join(iter(lambda: os.read(fd, 1024 * 1024), b''))


def _verify_record(directory_fd, name, record):
    """Check one artifact against size and digest through a single opened FD; returns its bytes."""
    fd = _open_regular(directory_fd, name, record['bytes'])
    try:
        data = _read_fd(fd)
    finally:
        os.close(fd)
    if len(data) != record['bytes'] or digest(data) != record['sha256']:
        raise ValueError(f'{name}: size/digest mismatch')
    return data


def verify_bundle(directory, approved_sha256, executables):
    """Verify the approval, schema and every declared byte. Creates nothing."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = os.open(directory, flags)
    try:
        fd = _open_regular(root, 'manifest.json', MAX_MANIFEST)
        try:
            raw = _read_fd(fd)
        finally:
            os.close(fd)
        manifest = verify_manifest(raw, approved_sha256, )
        if set(os.listdir(root)) != {'manifest.json', *manifest['artifacts']}:
            raise ValueError('bundle artifact set differs from manifest')
        for name, record in manifest['artifacts'].items():
            _verify_record(root, name, record)
    finally:
        os.close(root)
    root = os.open(executables, flags)
    try:
        if set(os.listdir(root)) != set(ROLES):
            raise ValueError('executable role set differs from manifest')
        for role, pin in manifest['executables'].items():
            verify_static_elf(_verify_record(root, role, pin))
    finally:
        os.close(root)
    return manifest


def verify_static_elf(data):
    """No shebang, loader or DT_NEEDED: the closure of this image is the image itself."""
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('executable is not a little-endian ELF64 image')
    kind, machine = struct.unpack_from('<HH', data, 16)
    phoff, phentsize, phnum = struct.unpack_from('<Q', data, 32)[0], *struct.unpack_from('<HH', data, 54)
    if kind not in (2, 3) or machine != 183 or phentsize != 56 or phnum == 0:
        raise ValueError('executable is not an aarch64 program image')
    if phoff + phnum * phentsize > len(data):
        raise ValueError('truncated ELF program headers')
    for index in range(phnum):
        segment, _flags, offset, _vaddr, _paddr, filesz = struct.unpack_from('<IIQQQQ', data, phoff + index * phentsize)
        if segment == 3:
            raise ValueError('dynamic loader closure is not bound')
        if segment == 2:
            if offset + filesz > len(data):
                raise ValueError('truncated ELF dynamic section')
            for position in range(offset, offset + filesz - 15, 16):
                tag = struct.unpack_from('<q', data, position)[0]
                if tag == 0:
                    break
                if tag == 1:
                    raise ValueError('dynamic library closure is not bound')


def _lease(value, name, kind, policy):
    keys(value, ['kind', 'value'])
    if value['kind'] != kind:
        raise ValueError('UID/GID roles are not interchangeable')
    low, high = policy['leases'][name]
    return integer(value['value'], low, high)


def _writable_path(path, policy):
    """Mirror kilnd's validate_writable_path, including its byte and count limits."""
    if (not isinstance(path, str) or len(path.encode('utf-8')) > policy['admission']['max_writable_path_bytes']
            or path == '/' or not path.startswith('/') or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in path)):
        raise ValueError('invalid writable path')
    if any(part in ('', '.', '..') for part in path[1:].split('/')):
        raise ValueError('invalid writable path')


def _inner_spec(spec, policy):
    limits = policy['admission']
    keys(spec, ['image', 'memory_bytes', 'cpu_millis', 'pids', 'disk_bytes', 'network',
                'read_only_root', 'writable_paths'])
    if spec['image'] not in limits['inner_images'] or spec['network'] != limits['inner_network']:
        raise ValueError('unsupported inner image or network')
    if type(spec['read_only_root']) is not bool:
        raise ValueError('invalid read-only flag')
    integer(spec['memory_bytes'], 1, limits['inner_memory_max'])
    integer(spec['cpu_millis'], 1, limits['inner_cpu_millis_max'])
    integer(spec['pids'], 1, 2**32 - 1)
    integer(spec['disk_bytes'], 1, U64)
    paths = spec['writable_paths']
    if not isinstance(paths, list) or len(paths) > limits['max_writable_paths'] or (paths and not spec['read_only_root']):
        raise ValueError('invalid writable paths')
    for path in paths:
        _writable_path(path, policy)
    if len(set(paths)) != len(paths):
        raise ValueError('duplicate writable path')


def spec_binding(host_spec):
    keys(host_spec, [*contract()['guest_exec_spec_fields'], 'labels'])
    guest = {key: value for key, value in host_spec.items() if key != 'labels'}
    _inner_spec(guest, contract())
    labels = host_spec['labels']
    if not isinstance(labels, dict) or len(labels) > 32:
        raise ValueError('invalid labels')
    for key, value in labels.items():
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,63}', key)
                or not isinstance(value, str) or len(value.encode('utf-8')) > 256
                or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value)):
            raise ValueError('invalid label')
    return {'host_spec': copy.deepcopy(host_spec),
            'host_spec_sha256': digest(canonical(host_spec)),
            'guest_exec_spec_sha256': digest(canonical(guest))}


def _identity_vector(vector, manifest):
    """Node-local inode values come only from verified installed descriptors."""
    keys(vector, ROLES)
    inodes = set()
    for role in ROLES:
        record = vector[role]
        keys(record, ['role', 'st_dev', 'st_ino', 'bytes', 'sha256', 'installation_generation'])
        pin = manifest['executables'][role]
        if record['role'] != role or record['bytes'] != pin['bytes'] or record['sha256'] != pin['sha256']:
            raise ValueError('executable identity differs from approved pin')
        for name in ['st_dev', 'st_ino', 'installation_generation']:
            integer(record[name], 1, U64)
        integer(record['bytes'], 1, MAX_ARTIFACT)
        inodes.add((record['st_dev'], record['st_ino']))
    if len(inodes) != len(ROLES):
        raise ValueError('executable roles alias one inode')


def _work_uuid(value):
    if not isinstance(value, str):
        raise ValueError('work UUID')
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError('work UUID') from error
    if str(parsed) != value or parsed.version != 4:
        raise ValueError('fresh canonical UUIDv4 required')


def verify_substitutions(values, manifest):
    """The exhaustive typed substitution table: no key outside it, no untyped value."""
    policy = manifest['launch_contract']
    keys(values, policy['substitutions'])
    matching(values['instance_id'], ID128)
    matching(values['allocation_id'], ID128)
    matching(values['sandbox_id'], SANDBOX_ID)
    matching(values['boot_nonce'], DIGEST)
    uid = _lease(values['uid'], 'uid', 'VmmUid', policy)
    gid = _lease(values['gid'], 'gid', 'VmmGid', policy)
    if (_lease(values['relay_uid'], 'uid', 'RelayUid', policy) == uid
            or _lease(values['relay_gid'], 'gid', 'RelayGid', policy) == gid):
        raise ValueError('relay lease overlaps VMM lease')
    integer(values['cid'], *policy['leases']['cid'])
    _work_uuid(values['work_uuid'])
    _inner_spec(values['inner_spec'], policy)
    _identity_vector(values['executables'], manifest)


def _expand(value, values):
    if isinstance(value, dict):
        return {key: _expand(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item, values) for item in value]
    if isinstance(value, str):
        whole = PLACEHOLDER.fullmatch(value)
        if whole:
            return values[whole[1]]
        return PLACEHOLDER.sub(lambda match: str(values[match[1]]), value)
    return value


def work_bytes(disk_bytes, work):
    rounded = (disk_bytes + work['guest_headroom_bytes'] + work['round_bytes'] - 1) // work['round_bytes'] * work['round_bytes']
    return max(work['minimum_bytes'], rounded)


def plan(raw_manifest, approved_sha256, substitutions):
    """Production has no constructible plan until the reviewed B4/B5/B7 gates."""
    verify_manifest(raw_manifest, approved_sha256)
    raise ValueError('production disabled')


def verify_plan(raw_manifest, approved_sha256, substitutions, actual):
    plan(raw_manifest, approved_sha256, substitutions)


def verify_config_bytes(prepared, raw):
    """Check the serialized /config.json; key order is immaterial, drive order is not."""
    if canonical(strict_json(raw)) != canonical(prepared['launch']['firecracker']):
        raise ValueError('serialized Firecracker configuration deviates from plan')


def launch_digest(prepared):
    """Covers config, argv and resolved recipe, including the identity drive; never its content."""
    return digest(canonical(prepared['launch']))


def plan_digest(prepared):
    return digest(canonical(prepared))


def verify_vmm_argv(prepared, argv):
    """Exact VMM argv. Only the three jailer timing values vary; their names and order do not."""
    template = contract()['vmm_argv']
    if not isinstance(argv, list) or len(argv) != len(template):
        raise ValueError('unexpected VMM argv')
    values = {'backend_id': 'fc-' + prepared['substitutions']['allocation_id']}
    for index, item in enumerate(template):
        if item in ('$start_time_us', '$start_time_cpu_us', '$parent_cpu_time_us'):
            value = argv[index]
            if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
                raise ValueError('invalid jailer timing diagnostic')
            integer(int(value), 0, U64)
            values[item[1:]] = value
    if argv != _expand(template, values):
        raise ValueError('unexpected VMM argv flags/order')


def verify_observation(expected, observed):
    """Actual executed identity. Argv and earlier hashes cannot authorize another inode."""
    keys(observed, contract()['executable']['observed_fields'])
    for name in observed:
        if type(observed[name]) is not type(expected[name]) or observed[name] != expected[name]:
            raise ValueError('actual executable identity disagrees with retained FD')


def verify_reopen(expected, reopened):
    """Helper restart: the protected reopen must find the identical installed generation."""
    keys(reopened, contract()['executable']['identity_fields'])
    if canonical(reopened) != canonical(expected):
        raise ValueError('reopened executable differs from journaled identity')


def verify_vmm_status(prepared, status):
    """Compare /proc/<vmm>/status with the frozen credentials. Only B4 can observe the real VMM."""
    fields = {}
    for line in status.splitlines():
        name, separator, value = line.partition(':')
        if separator:
            if name in fields:
                raise ValueError('duplicate status field')
            fields[name] = value.split()
    credentials = prepared['launch']['resource_recipe']['vmm_credentials']
    expected = {'Uid': [str(credentials['uid'])] * 4, 'Gid': [str(credentials['gid'])] * 4,
                'Groups': [str(group) for group in credentials['groups']],
                'NoNewPrivs': [str(credentials['NoNewPrivs'])],
                'Seccomp': [str(credentials['status_seccomp'])]}
    for name in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        expected[name] = [format(credentials[name], '016x')]
    for name, value in expected.items():
        if fields.get(name) != value:
            raise ValueError(f'VMM credentials differ from contract: {name}')


def bootstrap_record(prepared, plan_generation, jail_root):
    """FD 4's first message: binds the retained VMM inode, its label and the pinned jail root."""
    integer(plan_generation, 1, U64)
    keys(jail_root, ['st_dev', 'st_ino', 'mount_id'])
    for value in jail_root.values():
        integer(value, 1, U64)
    vmm = prepared['substitutions']['executables']['firecracker']
    handoff = prepared['launch']['resource_recipe']['handoff']
    raw = canonical({'version': handoff['version'], 'plan_generation': plan_generation,
                     'vmm_identity': {name: vmm[name] for name in ['st_dev', 'st_ino', 'bytes', 'sha256']},
                     'exec_file_label': prepared['launch']['executable_paths']['firecracker'],
                     'jail_root_identity': jail_root})
    if len(raw) > handoff['bootstrap_max_bytes']:
        raise ValueError('bootstrap record exceeds its bound')
    return raw


def verify_bootstrap(prepared, plan_generation, jail_root, raw):
    if bytes(raw) != bootstrap_record(prepared, plan_generation, jail_root):
        raise ValueError('bootstrap record differs from plan')


def identity_block(prepared):
    """vdc: a 4096-byte raw record. The plan never contains it, so the launch digest cannot."""
    values = prepared['substitutions']
    record = {name: values[name] for name in
              ['instance_id', 'allocation_id', 'sandbox_id', 'boot_nonce', 'work_uuid']}
    record.update(manifest_sha256=matching(prepared['manifest_sha256'], DIGEST),
                  launch_sha256=launch_digest(prepared),
                  guest_exec_spec_sha256=digest(canonical(values['inner_spec'])))
    payload = canonical(record)
    if not 1 <= len(payload) <= 4088:
        raise ValueError('identity record length')
    return b'KID1' + struct.pack('>I', len(payload)) + payload + bytes(4088 - len(payload))


def read_identity(block):
    """What init and the broker require: one framed canonical record and zero padding."""
    if len(block) != 4096 or block[:4] != b'KID1':
        raise ValueError('identity framing')
    length, = struct.unpack('>I', block[4:8])
    if not 1 <= length <= 4088 or any(block[8 + length:]):
        raise ValueError('identity length/padding')
    raw = bytes(block[8:8 + length])
    record = strict_json(raw)
    keys(record, contract()['identity']['fields'])
    matching(record['instance_id'], ID128)
    matching(record['allocation_id'], ID128)
    matching(record['sandbox_id'], SANDBOX_ID)
    for name in ['boot_nonce', 'manifest_sha256', 'launch_sha256', 'guest_exec_spec_sha256']:
        matching(record[name], DIGEST)
    _work_uuid(record['work_uuid'])
    if canonical(record) != raw:
        raise ValueError('identity JSON not canonical')
    return record


def verify_identity(block, prepared):
    """The host's comparison with its journal: a well-formed record for another boot fails."""
    if read_identity(block) != read_identity(identity_block(prepared)):
        raise ValueError('identity block binds a different session')

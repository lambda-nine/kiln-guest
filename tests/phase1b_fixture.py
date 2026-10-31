"""Test-only fixture schema and types. Never imported by production scripts.

FixturePlan has no PreparedCreate conversion; serialized documents carry a separate
schema/profile. Production entry points unconditionally refuse them, even reapproved.
"""
from dataclasses import dataclass
import copy
import os
from pathlib import Path
import phase1b_contract as p1
from phase1b_contract import (canonical, digest, matching, integer, keys, strict_json,
    contract, manifest_fields, manifest_inputs, verify_substitutions, work_bytes,
    verify_static_elf, DIGEST, ROLES, ARTIFACTS, MAX_ARTIFACT, MAX_MANIFEST, U64,
    TIMING, _open_regular, _read_fd, _verify_record, _expand)

FIXTURE_MANIFEST_SCHEMA = 'kiln-test-manifest-v1'
FIXTURE_PLAN_SCHEMA = 'kiln-test-plan-v1'
FIXTURE_PROFILE = 'test-only-b1'

@dataclass(frozen=True)
class FixturePlan:
    document: dict

# Fixture manifests name these exactly. B4 and B5 supply the real patch and broker.
FIXTURE_PROVENANCE = 'b1-fixture-static-aarch64-elf-v1'
FIXTURE_JAILER_PATCH = b'B1 fixture: stands in for the reviewed jailer patch B4 supplies. Not a patch.\n'
FIXTURE_BROKER_COMMIT = 'd94996c9f1d9795b3a47d9ffc71d40c452a2e6ee'


def fixture_inputs(artifacts):
    return {'provenance': FIXTURE_PROVENANCE, 'broker_source_commit': FIXTURE_BROKER_COMMIT,
            'jailer_patch_sha256': digest(FIXTURE_JAILER_PATCH),
            # A fixture's only source inputs are its own artifact bytes.
            'source_inventory_sha256': digest(canonical(artifacts))}


def verify_manifest(raw, approved_sha256):
    """Authenticate exact bytes, then the complete schema. Returns the parsed manifest."""
    matching(approved_sha256, DIGEST)
    if digest(raw) != approved_sha256:
        raise ValueError('independent manifest approval mismatch')
    manifest = strict_json(raw)
    policy = contract()
    fixed = {**manifest_fields(policy), 'schema': FIXTURE_MANIFEST_SCHEMA}
    if not isinstance(manifest, dict) or manifest.get('schema') != fixed['schema']:
        raise ValueError('unsupported Phase 1b manifest (legacy no-vsock is refused)')
    keys(manifest, [*fixed, 'fixture_only', 'artifacts', 'executables', 'inputs'])
    for name, expected in fixed.items():
        if canonical(manifest[name]) != canonical(expected):
            raise ValueError(f'unsupported Phase 1b manifest field: {name}')
    if type(manifest['fixture_only']) is not bool:
        raise ValueError('invalid fixture flag')
    keys(manifest['artifacts'], ARTIFACTS)
    for record in manifest['artifacts'].values():
        keys(record, ['bytes', 'sha256'])
        integer(record['bytes'], 1, MAX_ARTIFACT)
        matching(record['sha256'], DIGEST)
    keys(manifest['executables'], ROLES)
    seen = set()
    for pin in manifest['executables'].values():
        keys(pin, ['bytes', 'sha256', 'format', 'dependencies'])
        integer(pin['bytes'], 1, MAX_ARTIFACT)
        seen.add(matching(pin['sha256'], DIGEST))
        if pin['format'] != policy['executable']['format'] or pin['dependencies'] != []:
            raise ValueError('initial profile requires static ELF; unbound loader refused')
    if len(seen) != len(ROLES):
        raise ValueError('one executable image cannot serve two roles')
    # B1 supplies fixture manifests only, never a substitute production manifest.
    if manifest['fixture_only'] is not True:
        raise ValueError('production disabled: broker/patched-jailer/bundle approval absent')
    expected = {**manifest_inputs(policy), **fixture_inputs(manifest['artifacts'])}
    if canonical(manifest['inputs']) != canonical(expected):
        raise ValueError('input recipe mismatch')
    return manifest


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
        manifest = verify_manifest(raw, approved_sha256)
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


def plan(raw_manifest, approved_sha256, substitutions, labels=None):
    """Expand the approved template into the complete plan. Allocates nothing."""
    manifest = verify_manifest(raw_manifest, approved_sha256)
    policy = manifest['launch_contract']
    values = copy.deepcopy(substitutions)
    verify_substitutions(values, manifest)
    backend = 'fc-' + values['allocation_id']
    cgroup = 'kilnd-firecracker/' + values['instance_id'] + '/' + backend
    jail_root = '/var/lib/kilnd-helper/jails/firecracker/' + backend + '/root'
    vsock = jail_root + policy['firecracker']['vsock']['uds_path']
    if len(vsock.encode()) >= 108:
        raise ValueError('vsock path exceeds sockaddr_un')
    spec = values['inner_spec']
    work = work_bytes(spec['disk_bytes'], policy['work'])
    disk = work + policy['work']['host_allowance_bytes']
    if disk > U64:
        raise ValueError('reservation exceeds u64')
    backing = '/var/lib/kilnd-helper/work/' + values['instance_id'] + '/' + backend + '/work.xfs'
    paths = {role: policy['executable']['store'].format(sha256=values['executables'][role]['sha256'], role=role)
             for role in ROLES}
    typed = {**paths, 'backend_id': backend, 'vmm_cgroup': cgroup + '/vm/vmm', 'cid': values['cid'],
             'uid': values['uid']['value'], 'gid': values['gid']['value'],
             'relay_uid': values['relay_uid']['value'], 'relay_gid': values['relay_gid']['value'],
             'work_uuid': values['work_uuid'], 'work_backing_path': backing, 'work_bytes': work}
    recipe = {name: _expand(policy[name], typed) for name in
              ['jail', 'work', 'cgroups', 'workers', 'shared', 'vmm_credentials', 'relay_credentials',
               'process', 'identity', 'handoff', 'timing_exception']}
    semantic, template = [], iter(policy['vmm_argv'])
    for item in template:
        if item in TIMING:
            next(template)
        else:
            semantic.append(item)
    admission = policy['admission']
    launch = {'firecracker': _expand(policy['firecracker'], typed),
              'jailer_argv': [str(item) for item in _expand(policy['jailer_argv'], typed)],
              'vmm_argv_semantic': _expand(semantic, typed),
              'formatter_argv': recipe['work']['formatter_argv'],
              'executable_paths': paths,
              'jail_root': jail_root,
              'vsock_host_path': vsock,
              'cgroup': cgroup,
              'work_backing_path': backing,
              'work_bytes': work,
              'reservation': {'memory_bytes': admission['guest_memory_bytes'] + admission['host_overhead_bytes'],
                              'disk_bytes': disk,
                              'pids': spec['pids'] + admission['guest_service_pids'] + admission['host_pids'],
                              'host_pids': admission['host_pids'],
                              'host_cpu_millis': admission['cpu_millis'],
                              'virtual_cpu_slots': admission['vcpu_slots']},
              'resource_recipe': recipe}
    binding = p1.spec_binding({**values['inner_spec'], 'labels': labels or {}})
    return FixturePlan({'schema': FIXTURE_PLAN_SCHEMA, 'profile': FIXTURE_PROFILE, **binding,
            'manifest_sha256': approved_sha256, 'substitutions': values, 'launch': launch})


def verify_plan(raw_manifest, approved_sha256, substitutions, actual):
    """Compare the object about to be used with an independent expansion."""
    if canonical(plan(raw_manifest, approved_sha256, substitutions).document) != canonical(actual):
        raise ValueError('effective configuration/argv/resource recipe mismatch')

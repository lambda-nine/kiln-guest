"""Shared conformance corpus runner/generator. All constructors here are test-only."""
import copy
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import phase1b_contract as p1
import phase1b_fixture as f1


def walk(value, path=()):
    yield list(path), value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk(v, (*path, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, (*path, i))


def mutate(base, case):
    value = copy.deepcopy(base)
    target = value
    for key in case['path'][:-1]:
        target = target[key]
    key = case['path'][-1]
    if case.get('remove'):
        del target[key]
    elif isinstance(target, list) and key == len(target):
        target.append(case['value'])
    else:
        target[key] = case['value']
    return value


def case_bytes(case, bases):
    if 'repeat_hex' in case:
        return bytes.fromhex(case['repeat_hex']) * case['repeat'] + bytes.fromhex(case['suffix_hex'])
    if 'raw_hex' in case:
        return bytes.fromhex(case['raw_hex'])
    return p1.canonical(mutate(bases[case['base']], case))


def validate(kind, raw, bases):
    value = p1.strict_json(raw)
    if kind == 'contract':
        p1.verify_contract(value)
    elif kind == 'guest_exec_spec':
        p1._inner_spec(value, p1.contract())
    elif kind == 'substitutions':
        p1.verify_substitutions(value, bases['fixture_manifest'])
        # Checked arithmetic is part of the plan contract too.
        raw_manifest = (json.dumps(bases['fixture_manifest'], sort_keys=True, indent=2)+'\n').encode()
        f1.plan(raw_manifest, p1.digest(raw_manifest), value)
    elif kind == 'host_spec':
        p1.spec_binding(value)
    elif kind == 'binding':
        p1.keys(value, ['host_spec', 'host_spec_sha256', 'guest_exec_spec_sha256'])
        if p1.canonical(value) != p1.canonical(p1.spec_binding(value['host_spec'])):
            raise ValueError('binding mismatch')
    elif kind == 'fixture_manifest':
        f1.verify_manifest(raw, p1.digest(raw))
        root = Path(__file__).resolve().parent / 'fixtures/firecracker'
        for group, prefix in [('artifacts', 'bundle'), ('executables', 'executables')]:
            for name, pin in value[group].items():
                data = (root / prefix / name).read_bytes()
                if len(data) != pin['bytes'] or p1.digest(data) != pin['sha256']:
                    raise ValueError('fixture byte mismatch')
    elif kind == 'fixture_plan':
        manifest = (json.dumps(bases['fixture_manifest'], sort_keys=True, indent=2)+'\n').encode()
        f1.verify_plan(manifest, p1.digest(manifest), bases['fixture_plan']['substitutions'], value)
    elif kind == 'production_manifest':
        p1.verify_manifest(raw, p1.digest(raw))
    elif kind != 'json':
        raise ValueError('unknown corpus kind')
    return p1.canonical(value)


def generate(dest):
    dest = Path(dest)
    manifest = json.loads((dest/'bundle/manifest.json').read_bytes())
    plan = json.loads((dest/'plan.json').read_bytes())
    spec = plan['substitutions']['inner_spec']
    host = {**spec, 'labels': {'tenant': 'alpha'}}
    binding = p1.spec_binding(host)
    bases = {'contract': p1.contract(), 'fixture_manifest': manifest, 'fixture_plan': plan,
             'guest_exec_spec': spec, 'host_spec': host, 'binding': binding,
             'substitutions': plan['substitutions']}
    cases = []
    def add(name, kind, raw, accept):
        case = {'name': name, 'kind': kind, 'raw_hex': raw.hex(), 'accept': accept}
        if accept:
            canonical = p1.canonical(p1.strict_json(raw))
            case.update(canonical_ascii=canonical.decode('ascii'), sha256=p1.digest(canonical))
        cases.append(case)
    for name, raw in [
        ('unicode-poc', '{"writable_paths":["/雪"]}'.encode()),
        ('unicode-order', '{"😀":1,"\ue000":2,"a":3,"雪":4}'.encode()),
        ('unicode-escape-pair', b'{"x":"\\ud83d\\ude00"}'),
        ('unicode-composed', '{"x":["é","é","\u2028","\u2029","\x7f","\uffff"]}'.encode()),
        ('escapes', b'{"x":"\\b\\f\\n\\r\\t\\u0000\\/\\\\\\\""}'),
        ('integer-limits', b'[-9223372036854775808,18446744073709551615,0,9223372036854775808]'),
        ('depth-limit', b'['*32+b'0'+b']'*32),
        ('empty-at-depth-limit', b'['*32+b'{}'+b']'*32),
        ('scalars', b' [null,true,false,-17] \n'),
    ]: add(name, 'json', raw, True)
    for i, raw in enumerate([
        b'{"schema":1,"schema":2}', b'{"x":{"a":1,"\\u0061":2}}',
        b'1.0',b'1e3',b'1E+3',b'NaN',b'Infinity',b'-Infinity',b'-0',b'01',b'+1',
        b'18446744073709551616',b'-9223372036854775809',b'{"x":"\\ud800"}',
        b'{"\\udfff":1}',b'"\\ud800x"',b'"\\ud800\\ud800"',b'"\xed\xa0\x80"',
        b'"\xc0\xaf"',b'"\xff"',b'\xef\xbb\xbf{}',b'{}tail',b'',
        b'['*33+b'0'+b']'*33,b'['*32+b'{"k":0}'+b']'*32,
    ]): add(f'invalid-json-{i}', 'json', raw, False)
    for count, accept in [(p1.MAX_MANIFEST-1, True),(p1.MAX_MANIFEST, False)]:
        case={'name':'input-byte-limit-'+str(count+1),'kind':'json','repeat_hex':'20',
              'repeat':count,'suffix_hex':'30','accept':accept}
        if accept: case.update(canonical_ascii='0',sha256=p1.digest(b'0'))
        cases.append(case)
    for kind, base in bases.items():
        add('valid-'+kind,kind,p1.canonical(base),True)
        # Exhaustively mutate/remove every scalar AND container, not just hashes.
        for path, value in walk(base):
            if not path: continue
            if isinstance(value, bool): change = not value
            elif isinstance(value, int): change = value+1
            elif isinstance(value, str): change = value+'x'
            elif isinstance(value, list): change = value+['x']
            elif isinstance(value, dict): change = {**value, 'unknown': 1}
            else: change = 1
            for edit in [{'value': change}, {'remove': True}]:
                case = {'name':kind+':'+repr(path)+':'+str(bool(edit.get('remove'))),
                        'kind':kind,'base':kind,'path':path,**edit}
                raw = p1.canonical(mutate(base,case))
                try:
                    canonical = validate(kind,raw,bases)
                except (ValueError, TypeError):
                    case['accept'] = False
                else:
                    case.update(accept=True,canonical_ascii=canonical.decode(),sha256=p1.digest(canonical))
                cases.append(case)
    for path in ['/workspace/雪', '/workspace/😀', '/workspace/é', '/workspace/é', '/workspace/\uffff']:
        guest = {**spec, 'read_only_root': True, 'writable_paths':[path]}
        add('valid-path-'+path,'guest_exec_spec',p1.canonical(guest),True)
        add('host-path-'+path,'host_spec',p1.canonical({**guest,'labels':{'tenant':'雪😀'}}),True)
    for schema in [1, 2, 3, True, '2', None, f1.FIXTURE_MANIFEST_SCHEMA]:
        for fixture_only in [True, False]:
            add(f'production-schema-{schema}-{fixture_only}', 'production_manifest',
                p1.canonical({**manifest,'schema':schema,'fixture_only':fixture_only}),False)
    for bad in [1, True, [], None, {'labels':{}}, {**spec,'labels':{}}, {**spec,'pids':True},
                {**spec,'memory_bytes':'536870912'}, {**spec,'network':{'none':None}}]:
        add('schema-confusion-'+str(len(cases)), 'guest_exec_spec', p1.canonical(bad), False)
    for path, accept in [('/'+'雪'*341, True),('/'+'雪'*342, False),('/'+'a'*1023, True),('/'+'a'*1024, False)]:
        add('path-byte-bound-'+str(len(path.encode())), 'guest_exec_spec',
            p1.canonical({**spec,'read_only_root':True,'writable_paths':[path]}), accept)
    # Label collision PoC becomes both a valid host and a stale journal rejection.
    beta = {**host, 'labels': {'tenant': 'beta'}}
    add('label-beta','host_spec',p1.canonical(beta),True)
    add('label-collision-journal','binding',p1.canonical({**binding,'host_spec':beta}),False)
    for case in json.loads((dest/'negative-cases.json').read_text()):
        edit = {**case,'kind':'fixture_manifest','base':'fixture_manifest','accept':False}
        cases.append(edit)
    return {'format': 'b1-conformance-v1','bases': bases, 'cases': cases}

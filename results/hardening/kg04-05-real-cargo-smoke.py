#!/usr/bin/env python3
"""Host-side smoke of scripts/inputs.py against real crates and real Cargo; no VM and no guest build.

Usage: python3.12 kg04-05-real-cargo-smoke.py KILN_REPO KILN_COMMIT
Compiles only a one-line project against the kiln lock's own utf8parse entry,
which has no build script, and runs `cargo metadata` (no compile) for kiln itself.
"""
import hashlib, json, os, re, shutil, subprocess as sp, sys, tarfile, tempfile
from pathlib import Path
repo, commit = sys.argv[1:3]
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts'))
import inputs

def cargo(args, cwd, work):
    env = inputs.cargo_environment(os.environ, work)
    env.update({'CARGO_TARGET_DIR': str(Path(work)/'target'), 'CARGO_INCREMENTAL': '0',
                'RUSTFLAGS': f'--remap-path-prefix={work}=/build'})
    return sp.run(['cargo', *args, *inputs.cargo_arguments(Path(work)/'vendor')], cwd=cwd, env=env, capture_output=True, text=True)

with tempfile.TemporaryDirectory() as d:
    tmp = Path(d).resolve(); cache = tmp/'cache'
    kiln = tmp/'kiln-work'/'kiln'; kiln.mkdir(parents=True)
    archive = sp.run(['git', '-C', repo, 'archive', '--format=tar', commit], check=True, capture_output=True).stdout
    (tmp/'kiln.tar').write_bytes(archive)
    print('kiln_commit', commit, 'archive_sha256', hashlib.sha256(archive).hexdigest())
    sp.run(['tar', '-xf', tmp/'kiln.tar', '-C', kiln], check=True)

    print('\n== vendor the real kiln Cargo.lock over HTTPS, twice ==')
    a = inputs.vendor_crates(kiln, cache, tmp/'kiln-work')
    print('registry_packages', len(a['registry_packages']), 'local_packages', a['local_packages'], 'cargo_lock_sha256', a['cargo_lock_sha256'])
    (tmp/'kiln-b').mkdir(); (tmp/'kiln-b/kiln').mkdir(); sp.run(['tar', '-xf', tmp/'kiln.tar', '-C', tmp/'kiln-b/kiln'], check=True)
    b = inputs.vendor_crates(tmp/'kiln-b/kiln', cache, tmp/'kiln-b', fetcher=lambda *_: sys.exit('second extraction must not download'))
    print('second extraction from cached objects only; provenance identical:', a == b)
    vendor = tmp/'kiln-work/vendor'
    print('symlinks in vendor:', sum(1 for p in vendor.rglob('*') if p.is_symlink()))
    print('crates with build.rs:', sorted(p.parent.name for p in vendor.glob('*/build.rs')))
    uses = sorted({str(p.relative_to(vendor)) for p in vendor.rglob('*.rs') if re.search(r'env!\(\s*"CARGO_MANIFEST_DIR"', p.read_text(errors='replace'))})
    print('non-test files embedding CARGO_MANIFEST_DIR:', [u for u in uses if '/tests/' not in u and '/benches/' not in u])
    print('compiled build scripts using cc/pkg-config:', [p.name for p in vendor.iterdir() if p.name.split('-')[0] in ('cc', 'pkg')])
    print('unpacked vendor bytes:', sum(p.stat().st_size for p in vendor.rglob('*') if p.is_file()), 'cache files:', len(list((cache/'crates').iterdir())))

    print('\n== cargo metadata --frozen for kiln against the verified vendor ==')
    r = cargo(['metadata', '--format-version', '1'], kiln, tmp/'kiln-work')
    print('returncode', r.returncode, r.stderr.strip()[-400:])
    if r.returncode == 0:
        packages = json.loads(r.stdout)['packages']
        ids = [p for p in packages if p['source'] is not None]
        print('packages', len(packages), 'sources', sorted({p['source'] for p in ids}))
        print('all manifests under vendor:', all(p['manifest_path'].startswith(str(vendor)) for p in ids))

    print('\n== real Cargo compile of utf8parse: work-a, tamper, work-b ==')
    entry = next(p for p in a['registry_packages'] if p['name'] == 'utf8parse')
    def project(name):
        work = tmp/name; src = work/'project'/'src'; src.mkdir(parents=True)
        (work/'project/Cargo.toml').write_text(f'[package]\nname = "smoke"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nutf8parse = "={entry["version"]}"\n')
        (work/'project/Cargo.lock').write_text(f'version = 4\n\n[[package]]\nname = "smoke"\nversion = "0.1.0"\ndependencies = [\n "utf8parse",\n]\n\n[[package]]\nname = "utf8parse"\nversion = "{entry["version"]}"\nsource = "{entry["source"]}"\nchecksum = "{entry["sha256"]}"\n')
        (src/'main.rs').write_text('fn main() { let _ = utf8parse::Parser::new(); }\n')
        inputs.vendor_crates(work/'project', cache, work, fetcher=lambda *_: sys.exit('no download expected'))
        return work
    wa = project('work-a')
    r = cargo(['build', '--release'], wa/'project', wa)
    print('work-a build returncode', r.returncode, r.stderr.strip().splitlines()[-1:])
    print('cargo-home files after build:', sorted(str(p.relative_to(wa/'cargo-home')) for p in (wa/'cargo-home').rglob('*')))
    first_binary = (wa/'target/release/smoke').read_bytes()
    lib =wa/f'vendor/utf8parse-{entry["version"]}/src/lib.rs'
    lib.write_text('compile_error!("TAMPERED_CARGO_SOURCE_WAS_COMPILED");\n' + lib.read_text())
    shutil.rmtree(wa/'target')
    r = cargo(['build', '--release'], wa/'project', wa)
    print('tampered unpacked source: returncode', r.returncode)
    print('  compiled tampered source:', 'TAMPERED_CARGO_SOURCE_WAS_COMPILED' in r.stderr)
    print('  ' + ' '.join(r.stderr.split())[:300])
    wb = project('work-b')
    print('next independent extraction contains tamper:', 'TAMPERED' in (wb/f'vendor/utf8parse-{entry["version"]}/src/lib.rs').read_text())
    r = cargo(['build', '--release'], wb/'project', wb)
    print('work-b build returncode', r.returncode, r.stderr.strip().splitlines()[-1:])
    print('macOS smoke binary identical across work-a/work-b (not a guest reproducibility claim):', first_binary == (wb/'target/release/smoke').read_bytes())

    print('\n== tamper the cached compressed crate ==')
    crate = cache/f'crates/utf8parse-{entry["version"]}.crate'
    data = bytearray(crate.read_bytes()); data[len(data)//2] ^= 1; crate.write_bytes(data)
    try: project('work-c'); print('ACCEPTED')
    except ValueError as error: print('rejected:', str(error).replace(str(tmp), '$TMP'))
    print('extracted into work-c/vendor:', os.listdir(tmp/'work-c/vendor'))

    print('\n== inherited influences ==')
    wd = tmp/'work-d'; (wd/'project').mkdir(parents=True)
    os.environ['RUSTC_WRAPPER'] = '/nonexistent/evil-wrapper'
    os.environ['CARGO_BUILD_RUSTC_WRAPPER'] = '/nonexistent/evil-wrapper'
    os.environ['CARGO_HOME'] = str(tmp/'shared-home')
    crate.write_bytes(bytes(data[:len(data)//2]) + bytes([data[len(data)//2]^1]) + bytes(data[len(data)//2+1:]))
    shutil.rmtree(wd); wd = project('work-d')
    r = cargo(['build', '--release'], wd/'project', wd)
    print('build with hostile inherited env: returncode', r.returncode, 'shared home created:', (tmp/'shared-home').exists())

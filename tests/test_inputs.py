"""KG-04/05: verified Cargo sources, exact source stages, atomic output.

Runs on the host and in the VM. Only the real renameat2 exchange needs Linux;
elsewhere stage tests inject a portable exchange. Cargo.lock tests need Python
3.11+ for tomllib and skip under an older host python3.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import build
import inputs

HAS_TOMLLIB=importlib.util.find_spec('tomllib') is not None

def digest(data): return hashlib.sha256(data).hexdigest()

def swap(source,destination):
    """Stand-in for RENAME_EXCHANGE on hosts without renameat2; not atomic."""
    held=f'{destination}.held'
    os.rename(destination,held); os.rename(source,destination); os.rename(held,source)

def member(name,data=b'',mode=0o644,kind=tarfile.REGTYPE,link=''):
    info=tarfile.TarInfo(name); info.size=len(data) if kind==tarfile.REGTYPE else 0
    info.mode=mode; info.type=kind; info.linkname=link
    return info,io.BytesIO(data)

def tar_bytes(members,compression=''):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w'+compression,format=tarfile.PAX_FORMAT) as tar:
        for info,data in members: tar.addfile(info,data)
    return stream.getvalue()

def tree(root):
    root=Path(root)
    return {str(p.relative_to(root)):p.read_bytes() for p in sorted(root.rglob('*')) if p.is_file()}

def write_source(root,files):
    for name,data in files.items():
        path=Path(root)/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)

class Case(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.tmp=Path(directory.name).resolve()

class InventoryTests(Case):
    def source(self):
        root=self.tmp/'source'
        write_source(root,{'README.md':b'read\n','AGENTS.md':b'agents\n','.gitignore':b'/dist/\n',
            'config/pins.json':b'{}\n','scripts/a.py':b'#!/\n','tests/t.py':b't\n','src/init.c':b'c\n'})
        (root/'scripts/a.py').chmod(0o755)
        write_source(root,{'.git':b'gitdir: elsewhere\n','results/x.log':b'r\n','dist/bundle/Image':b'i\n',
            'scripts/__pycache__/a.pyc':b'p','src/results/y':b'y','config/dist/z':b'z',inputs.MANIFEST:b'stale'})
        return root

    def stage(self,root):
        (root/inputs.MANIFEST).write_text(json.dumps(inputs.source_inventory(root)))

    def test_inventory_is_complete_sorted_and_excludes_non_source(self):
        inventory=inputs.source_inventory(self.source())
        paths=[r['path'] for r in inventory['files']]
        self.assertEqual(paths,['.gitignore','AGENTS.md','README.md','config/pins.json','scripts/a.py','src/init.c','tests/t.py'])
        record=next(r for r in inventory['files'] if r['path']=='scripts/a.py')
        self.assertEqual(record,{'path':'scripts/a.py','mode':0o755,'size':4,'sha256':digest(b'#!/\n')})

    def test_digest_is_stable_and_covers_content_and_mode(self):
        root=self.source()
        first=inputs.inventory_digest(inputs.source_inventory(root))
        os.utime(root/'README.md',(1,1))
        self.assertEqual(first,inputs.inventory_digest(inputs.source_inventory(root)))
        (root/'README.md').chmod(0o600)
        moded=inputs.inventory_digest(inputs.source_inventory(root))
        self.assertNotEqual(first,moded)
        (root/'README.md').write_bytes(b'READ\n')
        self.assertNotEqual(moded,inputs.inventory_digest(inputs.source_inventory(root)))

    def test_symlink_and_special_are_rejected(self):
        root=self.source(); (root/'config/link').symlink_to('pins.json')
        with self.assertRaisesRegex(ValueError,'symlink'): inputs.source_inventory(root)
        (root/'config/link').unlink(); os.mkfifo(root/'config/fifo')
        with self.assertRaisesRegex(ValueError,'special'): inputs.source_inventory(root)

    def test_setuid_source_is_rejected(self):
        root=self.source(); (root/'README.md').chmod(0o4755)
        with self.assertRaisesRegex(ValueError,'setuid'): inputs.source_inventory(root)

    def test_verify_accepts_exact_stage_and_ignores_non_source(self):
        root=self.source(); self.stage(root)
        result=inputs.verify_source(root)
        self.assertEqual(result['digest'],inputs.inventory_digest(inputs.source_inventory(root)))
        write_source(root,{'scripts/__pycache__/b.pyc':b'q','results/later.log':b'l'})
        self.assertEqual(result,inputs.verify_source(root))

    def test_verify_rejects_each_drift(self):
        def missing(root): (root/'src/init.c').unlink()
        def extra(root): write_source(root,{'src/extra.h':b'#define EVIL\n'})
        def extra_dot(root): write_source(root,{'.cargo/config.toml':b'[build]\n'})
        def altered(root): (root/'config/pins.json').write_bytes(b'{"x":1}\n')
        def same_size(root): (root/'config/pins.json').write_bytes(b'[]\n')
        def mode(root): (root/'scripts/a.py').chmod(0o644)
        def linked(root):
            (root/'src/init.c').unlink(); (root/'src/init.c').symlink_to('../README.md')
        def empty(root): (root/'src/empty').mkdir()
        for name,change,expected in [('missing',missing,'missing src/init.c'),('extra',extra,'extra src/extra.h'),
                ('dotfile',extra_dot,'extra .cargo/config.toml'),('altered',altered,'altered config/pins.json'),
                ('same size',same_size,'altered config/pins.json'),('mode',mode,'altered scripts/a.py'),
                ('symlink',linked,'symlink'),('directory',empty,'extra directory src/empty')]:
            with self.subTest(name):
                shutil.rmtree(self.tmp/'source',ignore_errors=True)
                root=self.source(); self.stage(root); change(root)
                with self.assertRaisesRegex(ValueError,expected): inputs.verify_source(root)

    def test_verify_requires_a_regular_well_formed_manifest(self):
        root=self.source(); (root/inputs.MANIFEST).unlink()
        with self.assertRaises(OSError): inputs.verify_source(root)
        (root/'other.json').write_text('{"schema":1,"files":[]}'); (root/inputs.MANIFEST).symlink_to('other.json')
        with self.assertRaises(OSError): inputs.verify_source(root)
        (root/inputs.MANIFEST).unlink()
        (root/'other.json').unlink()
        for bad in ['[]','{"schema":2,"files":[]}','{"schema":1,"files":[{"path":"../x","mode":420,"size":0,"sha256":"%s"}]}'%('0'*64)]:
            (root/inputs.MANIFEST).write_text(bad)
            with self.assertRaises(ValueError): inputs.verify_source(root)

class StageTests(Case):
    def source(self,files=None):
        root=self.tmp/'source'; shutil.rmtree(root,ignore_errors=True)
        write_source(root,files or {'README.md':b'current\n','config/kernel.config':b'CONFIG_X=y\n','.hidden':b'h\n'})
        return root

    def archive(self,root):
        stream=io.BytesIO(); inputs.write_archive(root,stream); return stream.getvalue()

    def stage(self,data,**kw):
        kw.setdefault('exchange',swap)
        return inputs.stage_archive(io.BytesIO(data),self.tmp/'repo',**kw)

    def manifest(self,records):
        data=json.dumps({'schema':1,'files':records}).encode()
        return member(inputs.MANIFEST,data)

    def record(self,path,data,mode=0o644):
        return {'path':path,'mode':mode,'size':len(data),'sha256':digest(data)}

    def assert_no_temporaries(self):
        self.assertEqual([p.name for p in self.tmp.glob('.repo.tmp-*')],[])

    def test_first_stage_is_exact_and_verifiable(self):
        root=self.source(); (root/'README.md').chmod(0o640)
        result=self.stage(self.archive(root),exchange=None)
        self.assertEqual(result['digest'],inputs.inventory_digest(inputs.source_inventory(root)))
        repo=self.tmp/'repo'
        self.assertEqual(inputs.verify_source(repo),result)
        self.assertEqual(stat.S_IMODE((repo/'README.md').stat().st_mode),0o640)
        self.assertEqual(stat.S_IMODE(repo.stat().st_mode),0o755)
        self.assert_no_temporaries()

    def test_deleted_file_is_gone_after_restage(self):
        """Baseline: stale-stage.py kept config/kernel.config by extracting over the tree."""
        self.stage(self.archive(self.source()))
        self.assertTrue((self.tmp/'repo/config/kernel.config').exists())
        write_source(self.tmp/'repo',{'scripts/__pycache__/old.pyc':b'stale bytecode'})
        self.stage(self.archive(self.source({'README.md':b'next\n'})))
        repo=self.tmp/'repo'
        self.assertFalse((repo/'config').exists())
        self.assertFalse((repo/'scripts').exists())
        self.assertEqual((repo/'README.md').read_bytes(),b'next\n')
        inputs.verify_source(repo)
        self.assert_no_temporaries()

    def test_every_malformed_archive_leaves_old_stage_untouched(self):
        self.stage(self.archive(self.source()))
        repo=self.tmp/'repo'; before=tree(repo); inode=repo.stat().st_ino
        good=b'data\n'
        records=[self.record('a',good)]
        head=lambda: self.manifest(records)
        valid=self.archive(self.source())
        cases={
            'garbage':b'not a tar archive'*100,
            'empty':b'',
            'truncated':valid[:600],
            'no manifest':tar_bytes([member('a',good)]),
            'manifest not first':tar_bytes([member('a',good),head()]),
            'bad manifest json':tar_bytes([member(inputs.MANIFEST,b'{')]),
            'traversal':tar_bytes([head(),member('../escape',good)]),
            'absolute':tar_bytes([head(),member(str(self.tmp/'escape'),good)]),
            'dot':tar_bytes([head(),member('./a',good)]),
            'manifest traversal':tar_bytes([self.manifest([self.record('../escape',good)]),member('../escape',good)]),
            'manifest absolute':tar_bytes([self.manifest([self.record('/tmp/kg-escape',good)]),member('/tmp/kg-escape',good)]),
            'manifest excluded':tar_bytes([self.manifest([self.record('results/a',good)]),member('results/a',good)]),
            'manifest unsorted':tar_bytes([self.manifest([self.record('b',good),self.record('a',good)]),member('b',good),member('a',good)]),
            'duplicate':tar_bytes([head(),member('a',good),member('a',good)]),
            'duplicate manifest':tar_bytes([head(),member('a',good),head()]),
            'symlink':tar_bytes([head(),member('a',kind=tarfile.SYMTYPE,link='/etc/passwd')]),
            'hardlink':tar_bytes([head(),member('a',kind=tarfile.LNKTYPE,link='a')]),
            'fifo':tar_bytes([head(),member('a',kind=tarfile.FIFOTYPE)]),
            'device':tar_bytes([head(),member('a',kind=tarfile.CHRTYPE)]),
            'directory':tar_bytes([head(),member('a',kind=tarfile.DIRTYPE)]),
            'extra':tar_bytes([head(),member('a',good),member('extra',good)]),
            'omitted':tar_bytes([self.manifest(records+[self.record('b',good)]),member('a',good)]),
            'altered':tar_bytes([head(),member('a',b'DATA\n')]),
            'wrong size':tar_bytes([head(),member('a',good+b'x')]),
            'wrong mode':tar_bytes([head(),member('a',good,mode=0o755)]),
            'setuid mode':tar_bytes([self.manifest([self.record('a',good,0o4755)]),member('a',good,mode=0o4755)]),
        }
        exchanged=mock.Mock(side_effect=swap)
        for name,data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    inputs.stage_archive(io.BytesIO(data),repo,exchange=exchanged)
                exchanged.assert_not_called()
                self.assertEqual(tree(repo),before)
                self.assertEqual(repo.stat().st_ino,inode)
                self.assert_no_temporaries()
        self.assertFalse((self.tmp/'escape').exists())
        self.assertFalse(Path('/tmp/kg-escape').exists())

    def test_self_consistent_archive_must_match_expected_digest(self):
        root=self.source(); data=self.archive(root)
        expected=inputs.inventory_digest(inputs.source_inventory(root))
        self.stage(data,expected_digest=expected)
        before=tree(self.tmp/'repo')
        write_source(root,{'README.md':b'substituted\n'})
        with self.assertRaisesRegex(ValueError,'expected digest'):
            self.stage(self.archive(root),expected_digest=expected)
        self.assertEqual(tree(self.tmp/'repo'),before)

    def test_failed_publish_keeps_old_stage_and_removes_new(self):
        self.stage(self.archive(self.source()))
        before=tree(self.tmp/'repo')
        def fail(source,destination): raise OSError('exchange failed')
        with self.assertRaisesRegex(OSError,'exchange failed'):
            self.stage(self.archive(self.source({'README.md':b'next\n'})),exchange=fail)
        self.assertEqual(tree(self.tmp/'repo'),before)
        self.assert_no_temporaries()

    def test_destination_must_be_a_directory(self):
        data=self.archive(self.source())
        (self.tmp/'target').mkdir(); (self.tmp/'repo').symlink_to('target')
        with self.assertRaisesRegex(ValueError,'not a directory'): self.stage(data)
        self.assertEqual(list((self.tmp/'target').iterdir()),[])

    @unittest.skipUnless(sys.platform.startswith('linux'),'renameat2 is Linux-only')
    def test_real_exchange(self):
        self.stage(self.archive(self.source()),exchange=inputs.rename_exchange)
        self.stage(self.archive(self.source({'README.md':b'next\n'})),exchange=inputs.rename_exchange)
        self.assertEqual(sorted(tree(self.tmp/'repo')),[inputs.MANIFEST,'README.md'])
        self.assert_no_temporaries()

    @unittest.skipIf(sys.platform.startswith('linux'),'covers the non-Linux refusal')
    def test_exchange_refuses_outside_linux(self):
        (self.tmp/'a').mkdir(); (self.tmp/'b').mkdir()
        with self.assertRaisesRegex(OSError,'requires Linux'): inputs.rename_exchange(self.tmp/'a',self.tmp/'b')

    def test_program_runs_as_isolated_argument(self):
        """The VM gets this file as python3 -I -c with argv and tar on stdin."""
        root=self.source(); data=self.archive(root)
        expected=inputs.inventory_digest(inputs.source_inventory(root))
        program=(ROOT/'scripts/inputs.py').read_text()
        call=[sys.executable,'-I','-c',program,'stage',str(self.tmp/'repo'),expected]
        result=subprocess.run(call,input=data,capture_output=True,cwd=self.tmp)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['digest'],expected)
        inputs.verify_source(self.tmp/'repo')
        call[-1]='0'*64
        result=subprocess.run(call,input=data,capture_output=True,cwd=self.tmp)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'expected digest',result.stderr)

    def test_program_fits_one_remote_shell_argument(self):
        # limactl shell-quotes argv into one ssh command; Linux caps one exec argument at 128 KiB.
        self.assertLess(len(shlex.quote((ROOT/'scripts/inputs.py').read_text()))+4096,128*1024)

class CrateFixture(Case):
    def crate(self,name='demo',version='1.0.0',files=None,members=None):
        top=f'{name}-{version}'
        files=files if files is not None else {'Cargo.toml':b'[package]\nname="demo"\n','src/lib.rs':b'pub fn f() {}\n'}
        items=members if members is not None else [member(f'{top}/{path}',data) for path,data in files.items()]
        return tar_bytes(items,':gz')

    def project(self,crates,extra=''):
        """crates is [(name, version, bytes)]; returns kiln source, cache and a recording fetcher."""
        kiln=self.tmp/'kiln'; kiln.mkdir(exist_ok=True)
        text='version = 4\n\n[[package]]\nname = "kiln"\nversion = "0.1.0"\n\n'
        for name,version,data in crates:
            text+=f'[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{inputs.REGISTRY}"\nchecksum = "{digest(data)}"\n\n'
        (kiln/'Cargo.lock').write_text(text+extra)
        objects={f'https://static.crates.io/crates/{n}/{n}-{v}.crate':d for n,v,d in crates}
        calls=[]
        def fetcher(url,path):
            calls.append(url); Path(path).write_bytes(objects[url])
        return kiln,self.tmp/'cache',fetcher,calls

@unittest.skipUnless(HAS_TOMLLIB,'tomllib requires Python 3.11+')
class CargoLockTests(CrateFixture):
    def parse(self,body): return inputs.parse_cargo_lock('version = 4\n\n'+body)

    def test_rejects_every_other_source_and_shape(self):
        good=f'name = "a"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}"\nchecksum = "{"0"*64}"\n'
        cases={
            'git':f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "git+https://github.com/x/a#{"0"*40}"\n',
            'sparse':f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "sparse+https://index.crates.io/"\nchecksum = "{"0"*64}"\n',
            'lookalike':f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}.evil"\nchecksum = "{"0"*64}"\n',
            'no checksum':f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}"\n',
            'short checksum':f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}"\nchecksum = "abc"\n',
            'traversal name':f'[[package]]\nname = "../a"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}"\nchecksum = "{"0"*64}"\n',
            'traversal version':f'[[package]]\nname = "a"\nversion = "1.0.0/../../x"\nsource = "{inputs.REGISTRY}"\nchecksum = "{"0"*64}"\n',
            'duplicate':f'[[package]]\n{good}\n[[package]]\n{good}',
            'local checksum':f'[[package]]\nname = "a"\nversion = "1.0.0"\nchecksum = "{"0"*64}"\n',
            'replace':f'[[package]]\nname = "a"\nversion = "1.0.0"\nreplace = "b 1.0.0"\n',
            'unused patch':f'[[package]]\n{good}\n[[patch.unused]]\nname = "x"\nversion = "1.0.0"\n',
        }
        for name,body in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError): self.parse(body)
        with self.assertRaises(ValueError): inputs.parse_cargo_lock('version = 2\n\n[[package]]\nname = "a"\nversion = "1.0.0"\n')

    def test_accepts_registry_and_local_in_stable_order(self):
        body=''.join(f'[[package]]\nname = "{n}"\nversion = "1.0.0"\nsource = "{inputs.REGISTRY}"\nchecksum = "{"0"*64}"\n\n' for n in 'ba')
        registry,local=self.parse('[[package]]\nname = "kiln"\nversion = "0.1.0"\n\n'+body)
        self.assertEqual([p['name'] for p in registry],['a','b'])
        self.assertEqual(local,[{'name':'kiln','version':'0.1.0'}])

@unittest.skipUnless(HAS_TOMLLIB,'tomllib requires Python 3.11+')
class VendorTests(CrateFixture):
    def test_extraction_produces_checksums_cargo_can_verify(self):
        data=self.crate()
        kiln,cache,fetcher,calls=self.project([('demo','1.0.0',data)])
        result=inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)
        self.assertEqual(calls,['https://static.crates.io/crates/demo/demo-1.0.0.crate'])
        checksum=json.loads((self.tmp/'work/vendor/demo-1.0.0/.cargo-checksum.json').read_text())
        self.assertEqual(checksum,{'package':digest(data),'files':{'Cargo.toml':digest(b'[package]\nname="demo"\n'),'src/lib.rs':digest(b'pub fn f() {}\n')}})
        self.assertEqual(list((self.tmp/'work/cargo-home').iterdir()),[])
        self.assertEqual(result,{'cargo_lock_sha256':digest((kiln/'Cargo.lock').read_bytes()),
            'registry_packages':[{'name':'demo','version':'1.0.0','source':inputs.REGISTRY,'sha256':digest(data)}],
            'local_packages':[{'name':'kiln','version':'0.1.0'}]})
        self.assertEqual((cache/'crates/demo-1.0.0.crate').read_bytes(),data)
        self.assertEqual([p.name for p in (cache/'crates').iterdir()],['demo-1.0.0.crate'])

    def test_tampered_cached_crate_is_rejected_without_extraction_or_repair(self):
        data=self.crate()
        kiln,cache,fetcher,calls=self.project([('demo','1.0.0',data)])
        inputs.vendor_crates(kiln,cache,self.tmp/'work-a',fetcher)
        path=cache/'crates/demo-1.0.0.crate'
        evil=self.crate(files={'Cargo.toml':b'x','src/lib.rs':b'compile_error!("TAMPERED");'})
        path.write_bytes(evil)
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):
            inputs.vendor_crates(kiln,cache,self.tmp/'work-b',fetcher)
        self.assertEqual(os.listdir(self.tmp/'work-b/vendor'),[])
        self.assertEqual(path.read_bytes(),evil)
        self.assertEqual(len(calls),1)

    def test_crate_symlinked_in_cache_is_rejected(self):
        data=self.crate()
        kiln,cache,fetcher,_=self.project([('demo','1.0.0',data)])
        (cache/'crates').mkdir(parents=True); (self.tmp/'elsewhere').write_bytes(data)
        (cache/'crates/demo-1.0.0.crate').symlink_to(self.tmp/'elsewhere')
        with self.assertRaises(OSError): inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)

    def test_bad_download_is_not_cached(self):
        data=self.crate()
        kiln,cache,_,_=self.project([('demo','1.0.0',data)])
        def fetcher(url,path): Path(path).write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError,'download checksum'):
            inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)
        self.assertEqual(list((cache/'crates').iterdir()),[])

    def test_previous_vendor_mutation_cannot_reach_next_build(self):
        """Baseline: cargo-cache-run.sh compiled an edited shared registry/src tree."""
        data=self.crate()
        kiln,cache,fetcher,calls=self.project([('demo','1.0.0',data)])
        first=inputs.vendor_crates(kiln,cache,self.tmp/'work-a',fetcher)
        clean=tree(self.tmp/'work-a/vendor')
        (self.tmp/'work-a/vendor/demo-1.0.0/src/lib.rs').write_text('compile_error!("TAMPERED");')
        (self.tmp/'work-a/cargo-home/config.toml').write_text('[build]\nrustc-wrapper="/evil"\n')
        second=inputs.vendor_crates(kiln,cache,self.tmp/'work-b',fetcher)
        self.assertEqual(tree(self.tmp/'work-b/vendor'),clean)
        self.assertEqual(first,second)
        self.assertEqual(len(calls),1)
        self.assertEqual(list((self.tmp/'work-b/cargo-home').iterdir()),[])

    def test_existing_vendor_or_cargo_home_is_refused(self):
        kiln,cache,fetcher,_=self.project([('demo','1.0.0',self.crate())])
        for name in ['vendor','cargo-home']:
            with self.subTest(name):
                work=self.tmp/f'work-{name}'; (work/name).mkdir(parents=True)
                with self.assertRaises(FileExistsError): inputs.vendor_crates(kiln,cache,work,fetcher)

    def test_unsafe_crate_contents_are_rejected(self):
        top='demo-1.0.0'; cargo=lambda:member(f'{top}/Cargo.toml',b'x')
        cases={
            'symlink':[cargo(),member(f'{top}/link',kind=tarfile.SYMTYPE,link='/etc/passwd')],
            'hardlink':[cargo(),member(f'{top}/link',kind=tarfile.LNKTYPE,link=f'{top}/Cargo.toml')],
            'fifo':[cargo(),member(f'{top}/fifo',kind=tarfile.FIFOTYPE)],
            'device':[cargo(),member(f'{top}/dev',kind=tarfile.BLKTYPE)],
            'traversal':[cargo(),member(f'{top}/../escape',b'x')],
            'absolute':[cargo(),member('/tmp/kg-crate-escape',b'x')],
            'wrong top':[cargo(),member('demo-1.0.1/src/lib.rs',b'x')],
            'no top':[cargo(),member('lib.rs',b'x')],
            'top is a file':[member(top,b'x')],
            'duplicate':[cargo(),member(f'{top}/Cargo.toml',b'y')],
            'parent is a file':[cargo(),member(f'{top}/a',b'x'),member(f'{top}/a/b',b'x')],
            'no Cargo.toml':[member(f'{top}/src/lib.rs',b'x')],
            'planted checksum':[cargo(),member(f'{top}/.cargo-checksum.json',b'{}')],
        }
        for name,members in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.tmp/'work',ignore_errors=True); shutil.rmtree(self.tmp/'cache',ignore_errors=True)
                kiln,cache,fetcher,_=self.project([('demo','1.0.0',self.crate(members=members))])
                with self.assertRaises(ValueError): inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)
                self.assertFalse(Path('/tmp/kg-crate-escape').exists())

    def test_crate_modes_are_normalized(self):
        top='demo-1.0.0'
        data=self.crate(members=[member(f'{top}/Cargo.toml',b'x',mode=0o4777),member(f'{top}/run.sh',b'y',mode=0o700),member(f'{top}/src',kind=tarfile.DIRTYPE,mode=0o777)])
        kiln,cache,fetcher,_=self.project([('demo','1.0.0',data)])
        inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)
        vendor=self.tmp/'work/vendor'/top
        self.assertEqual(stat.S_IMODE((vendor/'Cargo.toml').stat().st_mode),0o755)
        self.assertEqual(stat.S_IMODE((vendor/'run.sh').stat().st_mode),0o755)
        self.assertEqual(stat.S_IMODE((vendor/'src').stat().st_mode),0o755)

    def test_inherited_cargo_config_is_refused(self):
        kiln,cache,fetcher,_=self.project([('demo','1.0.0',self.crate())])
        for directory in [self.tmp,kiln]:
            with self.subTest(str(directory)):
                write_source(directory,{'.cargo/config.toml':b'[build]\n'})
                with self.assertRaisesRegex(ValueError,'Cargo config'):
                    inputs.vendor_crates(kiln,cache,self.tmp/'work',fetcher)
                shutil.rmtree(directory/'.cargo')

class CargoInvocationTests(Case):
    def test_inherited_influences_are_cleared(self):
        env=inputs.cargo_environment({'PATH':'/pinned','RUSTC_WRAPPER':'/evil','RUSTC_WORKSPACE_WRAPPER':'/evil',
            'RUSTFLAGS':'-C evil','RUSTC':'/evil','RUSTDOC':'/evil','RUSTUP_TOOLCHAIN':'evil',
            'CARGO_HOME':'/shared','CARGO_ENCODED_RUSTFLAGS':'evil','CARGO_BUILD_RUSTC_WRAPPER':'/evil',
            'CARGO_SOURCE_CRATES_IO_REPLACE_WITH':'evil','CARGO_NET_OFFLINE':'false'},'/w/work-a')
        self.assertEqual(env,{'PATH':'/pinned','CARGO_HOME':'/w/work-a/cargo-home'})

    def test_arguments_force_the_verified_vendor_offline(self):
        self.assertEqual(inputs.cargo_arguments(Path('/w/work-a/vendor')),['--frozen',
            '--config','source.crates-io.replace-with="verified-vendor"',
            '--config','source.verified-vendor.directory="/w/work-a/vendor"'])

class OutputTests(Case):
    def test_existing_output_is_refused_before_any_work(self):
        final=self.tmp/'bundle-a'; final.mkdir(); (final/'Image').write_bytes(b'original')
        populate=mock.Mock()
        with self.assertRaisesRegex(ValueError,'refusing to overwrite'): inputs.publish_new_directory(final,populate)
        populate.assert_not_called()
        self.assertEqual(tree(final),{'Image':b'original'})

    def test_success_publishes_only_new_files_into_an_empty_directory(self):
        def populate(output):
            self.assertEqual(list(output.iterdir()),[])
            self.assertEqual(output.parent,self.tmp)
            (output/'Image').write_bytes(b'new')
        inputs.publish_new_directory(self.tmp/'bundle-a',populate)
        self.assertEqual(tree(self.tmp/'bundle-a'),{'Image':b'new'})
        self.assertEqual(stat.S_IMODE((self.tmp/'bundle-a').stat().st_mode),0o755)
        self.assertEqual(os.listdir(self.tmp),['bundle-a'])

    def test_failed_build_publishes_nothing_and_removes_partial_output(self):
        def populate(output):
            (output/'Image').write_bytes(b'partial'); raise RuntimeError('rootfs failed')
        with self.assertRaisesRegex(RuntimeError,'rootfs failed'):
            inputs.publish_new_directory(self.tmp/'bundle-a',populate)
        self.assertEqual(os.listdir(self.tmp),[])

    def test_output_created_during_build_is_not_replaced(self):
        def populate(output):
            (self.tmp/'bundle-a').mkdir(); (self.tmp/'bundle-a/Image').write_bytes(b'other')
            (output/'Image').write_bytes(b'mine')
        with self.assertRaises(OSError): inputs.publish_new_directory(self.tmp/'bundle-a',populate)
        self.assertEqual(tree(self.tmp/'bundle-a'),{'Image':b'other'})
        self.assertEqual(os.listdir(self.tmp),['bundle-a'])

class BuildScriptTests(Case):
    def test_reuse_kernel_is_gone(self):
        text=(ROOT/'scripts/build.py').read_text()
        self.assertNotIn('reuse',text)
        self.assertIn('--frozen',(ROOT/'scripts/inputs.py').read_text())
        self.assertNotIn("'--locked'",text)

    def test_lock_refuses_toolchain_or_deb_repin(self):
        lock={'schema':1,'toolchain':{'rustc':'1'},'debs':[{'package':'nft'}],'kiln_source_sha256':'old'}
        for key,value in [('toolchain',{'rustc':'2'}),('debs',[]),('schema',2)]:
            with self.subTest(key):
                with self.assertRaisesRegex(ValueError,'review an intentional repin'):
                    build.reconcile_lock(lock,{**lock,key:value},None)
        extra={**lock,'extra':1}
        with self.assertRaisesRegex(ValueError,'review an intentional repin'): build.reconcile_lock(extra,lock,None)

    def test_lock_follows_only_a_reviewed_kiln_pin(self):
        lock={'schema':1,'toolchain':{},'debs':[],'kiln_source_sha256':'old'}
        moved={**lock,'kiln_source_sha256':'new'}
        self.assertEqual(build.reconcile_lock(lock,moved,'new'),moved)
        self.assertEqual(build.reconcile_lock(lock,lock,None),lock)
        for pinned in [None,'other']:
            with self.assertRaisesRegex(ValueError,'kiln source differs'): build.reconcile_lock(lock,moved,pinned)
        self.assertEqual(build.reconcile_lock(None,moved,None),moved)

    def test_provenance_is_complete_and_path_free(self):
        cache=self.tmp/'cache-does-not-appear'; cache.mkdir()
        for name in ['kiln.tar','linux.tar.xz','alpine.tar.gz']: (cache/name).write_bytes(name.encode())
        lock={'debs':[{'package':'nft','sha256':'d'}],'toolchain':{'rustc':'r'}}
        cargo={'cargo_lock_sha256':'c','registry_packages':[],'local_packages':[]}
        source={'digest':'s','files':[]}
        result=build.input_provenance(cache,lock,source,cargo)
        self.assertEqual(result['kiln'],{'commit':build.PINS['kiln_commit'],'archive_sha256':digest(b'kiln.tar')})
        self.assertEqual(result['kernel_archive_sha256'],digest(b'linux.tar.xz'))
        self.assertEqual(result['alpine_archive_sha256'],digest(b'alpine.tar.gz'))
        self.assertEqual((result['build_lock'],result['cargo'],result['source']),(lock,cargo,source))
        self.assertEqual(result['build_lock_sha256'],inputs.sha(ROOT/'config/build-lock.json'))
        self.assertNotIn('cache-does-not-appear',json.dumps(result))

@unittest.skipUnless((ROOT/'.git').exists(),'the wrapper runs only from a git checkout')
class WrapperTests(Case):
    def setUp(self):
        super().setUp()
        import lima
        self.lima=lima

    def action(self,name):
        events=[]
        with mock.patch.object(self.lima,'LOCK',self.tmp/'lock'), \
                mock.patch.object(self.lima,'stage_source',side_effect=lambda:(events.append('stage'),'f'*64)[1]), \
                mock.patch.object(self.lima,'stage_kiln'), \
                mock.patch.object(self.lima,'shell',side_effect=lambda c,**k:events.append(c)), \
                mock.patch.object(sys,'argv',['lima.py',name]):
            self.lima.main()
        self.assertFalse((self.tmp/'lock').exists())
        return events

    def test_each_build_stages_fresh_and_binds_the_digest(self):
        for name,letter in [('build-a','a'),('build-b','b')]:
            with self.subTest(name):
                events=self.action(name)
                self.assertEqual(events[0],'stage')
                self.assertEqual(len(events),2)
                self.assertIn(f'--work /build/work-{letter} --out /build/bundle-{letter} --source-digest {"f"*64}',events[1])
                self.assertNotIn('CARGO_HOME',events[1])

    def test_prepare_names_kiln_from_the_common_dir_sibling(self):
        events=self.action('prepare')
        self.assertEqual(events[0],'stage')
        self.assertIn('--kiln-repo /build/kiln-source',events[1])
        self.assertIn('build_environment.py enter',events[1])
        self.assertNotIn('CARGO_HOME',events[1])
        self.assertEqual(self.lima.LOCK,self.lima.COMMON.parent.parent/'.vm-lock')

    def test_test_action_does_not_restage(self):
        self.assertEqual(len(self.action('test')),1)

    def test_collect_returns_config_before_any_bundle_exists(self):
        checkout=self.tmp/'checkout'; write_source(checkout,{'config/build-lock.json':b'old\n'})
        commands=[]
        def shell(command,stdout):
            commands.append(command)
            stdout.write(tar_bytes([member('repo/config/build-lock.json',b'new\n')]))
        with mock.patch.object(self.lima,'LOCK',self.tmp/'lock'),mock.patch.object(self.lima,'ROOT',checkout), \
                mock.patch.object(self.lima,'shell',side_effect=shell),mock.patch.object(sys,'argv',['lima.py','collect']):
            self.lima.main()
        self.assertIn('ls -d bundle-a bundle-b repo/config results',commands[0])
        self.assertEqual((checkout/'config/build-lock.json').read_bytes(),b'new\n')

    def fake_limactl(self,body):
        bin_dir=self.tmp/'bin'; bin_dir.mkdir()
        limactl=bin_dir/'limactl'
        limactl.write_text(f'#!/bin/sh\nshift 4\nif [ "$1" = sudo ]; then shift; fi\nif [ "$1" = python3 ]; then shift; fi\n{body}\n')
        limactl.chmod(0o755)
        return mock.patch.dict(os.environ,{'PATH':f'{bin_dir}:{os.environ["PATH"]}'})

    def test_stage_source_end_to_end_with_a_local_receiver(self):
        with self.fake_limactl(f'exec {shlex.quote(sys.executable)} "$@"'), \
                mock.patch.object(self.lima,'shell'), \
                mock.patch.object(self.lima,'BUILD_ROOT',str(self.tmp/'build')), \
                mock.patch.object(self.lima,'ROOT',self.tmp/'checkout'):
            write_source(self.tmp/'checkout',{'scripts/inputs.py':(ROOT/'scripts/inputs.py').read_bytes(),
                'config/pins.json':b'{}\n','results/x':b'r','.git':b'gitdir: x\n'})
            found=self.lima.stage_source()
        stage=self.tmp/'build/repo'
        self.assertEqual(inputs.verify_source(stage)['digest'],found)
        self.assertEqual(sorted(tree(stage)),[inputs.MANIFEST,'config/pins.json','scripts/inputs.py'])

    def test_stage_source_reports_receiver_rejection_without_a_broken_pipe(self):
        with self.fake_limactl('exit 7'), mock.patch.object(self.lima,'shell'), \
                mock.patch.object(self.lima,'ROOT',self.tmp/'checkout'):
            write_source(self.tmp/'checkout',{'scripts/inputs.py':b'x\n','big':b'x'*(4*1024*1024)})
            with self.assertRaisesRegex(RuntimeError,'staging failed'): self.lima.stage_source()

if __name__=='__main__': unittest.main()

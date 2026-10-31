"""KR-01 and Phase 1b B1: exact profiles and every security-relevant deviation fail closed."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess as sp
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
from generate_phase1b_fixtures import apply_mutation, generate
from exec_identity_fixture import CASES
from launch_contract import CMDLINE, FC_SUFFIX, PHASE1B_PROFILE, contract, profile, verify_launch, verify_jailer_argv
import phase1b_contract as p1
from privileged_launch import TRUST_ROOT, install_executable, open_executable, protected_directory, trusted_directory

class LaunchContractTests(unittest.TestCase):
    def test_all_profiles_and_deviations(self):
        manifest={'launch_contract':contract()}
        for profile, entry in contract()['profiles'].items():
            config=entry['firecracker']; jailer=entry['jailer']
            verify_launch(manifest,config,jailer,profile)
            mutations=[('boot-source','boot_args','nokaslr'),
                       ('machine-config','vcpu_count',2),('machine-config','mem_size_mib',512),
                       ('machine-config','smt',True),('machine-config','huge_pages','None'),
                       ('machine-config','track_dirty_pages',True),('machine-config','cpu_template','T2')]
            for section,key,value in mutations:
                changed=copy.deepcopy(config); changed[section][key]=value
                with self.assertRaises(ValueError): verify_launch(manifest,changed,jailer,profile)
            for key,value in [('vsock',{'guest_cid':3,'uds_path':'/vsock'}),
                              ('network-interfaces',[]),('drives',[])]:
                changed=copy.deepcopy(config); changed[key]=value
                if changed != config:
                    with self.assertRaises(ValueError): verify_launch(manifest,changed,jailer,profile)
            for i in range(2):
                changed=copy.deepcopy(config); changed['drives'][i]['is_read_only']=not changed['drives'][i]['is_read_only']
                with self.assertRaises(ValueError): verify_launch(manifest,changed,jailer,profile)
            for key,value in [('uid',0),('gid',0),('cgroup_version',1),('seccomp','disabled'),('parent_cgroup','other')]:
                changed=dict(jailer); changed[key]=value
                with self.assertRaises(ValueError): verify_launch(manifest,config,changed,profile)
            changed=copy.deepcopy(config); changed['drives'].reverse()
            with self.assertRaises(ValueError): verify_launch(manifest,changed,jailer,profile)

    def test_manifest_contract_cannot_silently_change(self):
        changed=contract(); changed['profiles']['production']['firecracker']['boot-source']['boot_args']+=' nokaslr'
        with self.assertRaises(ValueError):
            verify_launch({'launch_contract':changed},changed['profiles']['production']['firecracker'],
                          changed['profiles']['production']['jailer'],'production')

    def test_actual_jailer_argv_rejects_extra_and_weak_flags(self):
        manifest={'launch_contract':contract()}; config=contract()['profiles']['production']['firecracker']
        argv=['jailer','--id','boot','--exec-file','/verified/firecracker','--uid','10000','--gid','10000',
              '--cgroup-version','2','--chroot-base-dir','/private/jails','--','--api-sock','/api.sock','--config-file','/config.json']
        verify_jailer_argv(manifest,config,argv,'production',expected_jailer='jailer',expected_exec='/verified/firecracker',expected_base='/private/jails')
        for changed in [[s if i!=4 else '/untrusted/fc' for i,s in enumerate(argv)],
                        [s if i!=12 else '/untrusted/jails' for i,s in enumerate(argv)],
                        argv+['--no-seccomp'],argv[:13]+['--daemonize']+argv[13:],
                        [s if i!=6 else '0' for i,s in enumerate(argv)]]:
            with self.assertRaises(ValueError): verify_jailer_argv(manifest,config,changed,'production',expected_jailer='jailer',expected_exec='/verified/firecracker',expected_base='/private/jails')
        bad=copy.deepcopy(config); bad['machine-config']['vcpu_count']=True
        with self.assertRaises(ValueError): verify_launch(manifest,bad,contract()['profiles']['production']['jailer'])


FIXTURES=Path(__file__).resolve().parent/'fixtures/firecracker'
ROOT=FIXTURES.parents[2]
MIB=1024*1024
MISSING=object()

def load(name): return json.loads((FIXTURES/name).read_text())

def leaves(value,path=()):
    """Every container and scalar path; mutation tests exercise each one."""
    yield path,value
    if isinstance(value,dict):
        for key,item in value.items(): yield from leaves(item,path+(key,))
    elif isinstance(value,list):
        for index,item in enumerate(value): yield from leaves(item,path+(index,))

def changed(value):
    if isinstance(value,bool): return not value
    if isinstance(value,int): return value+1
    if isinstance(value,str): return value+'x'
    if isinstance(value,list): return value+['x']
    if isinstance(value,dict): return {**value,'unknown':1}
    return 1

def mutated(document,path,value=MISSING):
    copied=copy.deepcopy(document); target=copied
    for part in path[:-1]: target=target[part]
    if value is MISSING: del target[path[-1]]
    else: target[path[-1]]=value
    return copied


class Phase1bFixtureCase(unittest.TestCase):
    def setUp(self):
        self.raw=(FIXTURES/'bundle/manifest.json').read_bytes()
        self.approved=load('digests.json')['approved_manifest_sha256']
        self.manifest=json.loads(self.raw)
        self.subs=load('substitutions.json')
        self.plan=load('plan.json')

    def prepared(self,subs=None):
        return p1.plan(self.raw,self.approved,subs or self.subs,fixture_only=True)

    def bundle_dir(self,directory):
        bundle=Path(directory)/'bundle'; executables=Path(directory)/'executables'
        shutil.copytree(FIXTURES/'bundle',bundle); shutil.copytree(FIXTURES/'executables',executables)
        return bundle,executables

    def rewrite(self,bundle,document):
        raw=(json.dumps(document,sort_keys=True,indent=2)+'\n').encode()
        (bundle/'manifest.json').write_bytes(raw)
        return p1.digest(raw)


class Phase1bManifestTests(Phase1bFixtureCase):
    def test_golden_fixtures_regenerate_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'firecracker'; generate(dest)
            names=sorted(str(p.relative_to(dest)) for p in dest.rglob('*') if p.is_file())
            self.assertEqual(names,sorted(str(p.relative_to(FIXTURES)) for p in FIXTURES.rglob('*') if p.is_file()))
            for name in names: self.assertEqual((dest/name).read_bytes(),(FIXTURES/name).read_bytes(),name)

    def test_golden_bundle_passes_only_in_fixture_mode(self):
        p1.verify_bundle(FIXTURES/'bundle',self.approved,FIXTURES/'executables',fixture_only=True)
        for call in [lambda:p1.verify_manifest(self.raw,self.approved),
                     lambda:p1.verify_bundle(FIXTURES/'bundle',self.approved,FIXTURES/'executables')]:
            with self.assertRaisesRegex(ValueError,'production disabled'): call()

    def test_no_placeholder_security_fields(self):
        for name in ['plan.json','plan-equal-ids.json','bootstrap.json','substitutions.json']:
            for path,value in leaves(load(name)):
                if isinstance(value,str):
                    self.assertNotRegex(value,r'\$|\{|TODO|placeholder|PLACEHOLDER',(name,path))
        for path,value in leaves(self.manifest['artifacts']):
            if path and path[-1]=='sha256': self.assertRegex(value,r'^[0-9a-f]{64}$')

    def test_independent_approval_binds_exact_bytes(self):
        reformatted=json.dumps(self.manifest,sort_keys=True).encode()
        self.assertEqual(json.loads(reformatted),self.manifest)
        for raw,approved in [(self.raw,'00'*32),(self.raw,self.approved.upper()),(reformatted,self.approved),
                             (self.raw+b'\n',self.approved),(self.raw,'x')]:
            with self.assertRaisesRegex(ValueError,'approval mismatch|invalid identity'):
                p1.verify_manifest(raw,approved,fixture_only=True)

    def test_coordinated_image_and_manifest_substitution(self):
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            image=b'attacker kernel'; (bundle/'Image').write_bytes(image)
            forged=mutated(self.manifest,('artifacts','Image'),{'bytes':len(image),'sha256':p1.digest(image)})
            self.rewrite(bundle,forged)
            with self.assertRaisesRegex(ValueError,'approval mismatch'):
                p1.verify_bundle(bundle,self.approved,executables,fixture_only=True)

    def test_strict_json(self):
        good=b'{"a":1}'
        self.assertEqual(p1.strict_json(good),{'a':1})
        for raw in [b'{"a":1,"a":1}',b'{"a":1.0}',b'{"a":1e3}',b'{"a":NaN}',b'{"a":Infinity}',b'\xef\xbb\xbf{"a":1}',
                    '{"a":1}'.encode('utf-16'),b'{"a":"\xff"}',b'{"a":"\\ud800"}',b'{"\\ud800":1}',b'{"a":1}trailing',
                    b'',b'['*34+b']'*34,b'['*100000,b' '*(p1.MAX_MANIFEST+1)]:
            with self.assertRaises(ValueError,msg=raw[:24]): p1.strict_json(raw)

    def test_every_manifest_leaf_refused_even_when_reapproved(self):
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            count=0
            for path,value in leaves(self.manifest):
                if not path: continue
                for replacement in [changed(value),MISSING]:
                    approved=self.rewrite(bundle,mutated(self.manifest,path,replacement))
                    with self.assertRaises(ValueError,msg=(path,replacement)):
                        p1.verify_bundle(bundle,approved,executables,fixture_only=True)
                    count+=1
            self.assertGreater(count,400)
            self.assertEqual(self.rewrite(bundle,self.manifest),p1.digest((bundle/'manifest.json').read_bytes()))

    def test_named_attacks_refused_even_when_reapproved(self):
        cases=load('negative-cases.json')
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            for case in cases:
                document=copy.deepcopy(self.manifest); apply_mutation(document,case)
                self.assertNotEqual(document,self.manifest,case['name'])
                approved=self.rewrite(bundle,document)
                with self.assertRaises(ValueError,msg=case['name']):
                    p1.verify_bundle(bundle,approved,executables,fixture_only=True)

    def test_contract_pins_and_recipe_drift(self):
        pins=p1.inputs_pin()
        self.assertEqual(pins['contract_sha256'],p1.digest((ROOT/'config/phase1b-contract.json').read_bytes()))
        self.assertIs(pins['production_enabled'],False)
        self.assertEqual(pins['missing_artifacts'],['reviewed-patched-jailer','reviewed-broker','approved-three-drive-vsock-bundle'])
        with mock.patch.object(p1,'inputs_pin',return_value={**pins,'contract_sha256':'00'*32}):
            with self.assertRaisesRegex(ValueError,'contract recipe pin'): p1.contract()
        with mock.patch.object(p1,'inputs_pin',return_value={**pins,'handoff_recipe_sha256':'00'*32}):
            with self.assertRaisesRegex(ValueError,'handoff recipe pin'): p1.contract()
        self.assertEqual(load('contract.json'),p1.contract())
        self.assertEqual(p1.contract()['limits'],{'manifest_max_bytes':p1.MAX_MANIFEST,'artifact_max_bytes':p1.MAX_ARTIFACT})

    def test_frozen_section_values(self):
        c=p1.contract()
        self.assertEqual(c['firecracker']['boot-source']['boot_args'],CMDLINE)
        self.assertEqual(c['firecracker_cmdline_suffix'],FC_SUFFIX)
        self.assertEqual(c['firecracker']['machine-config'],{'vcpu_count':1,'mem_size_mib':768,'smt':False,'huge_pages':'Transparent','track_dirty_pages':False})
        self.assertEqual([d['drive_id'] for d in c['firecracker']['drives']],['rootfs','work','identity'])
        self.assertEqual([(d['is_root_device'],d['is_read_only']) for d in c['firecracker']['drives']],[(True,True),(False,False),(False,True)])
        self.assertEqual(set(c['firecracker']),{'boot-source','machine-config','drives','vsock'})
        self.assertEqual(c['firecracker']['vsock']['uds_path'],'/run/vsock.sock')
        self.assertEqual({k:c['vmm_credentials'][k] for k in ['groups','CapEff','CapPrm','CapInh','CapBnd','CapAmb','NoNewPrivs']},
                         {'groups':[],'CapEff':0,'CapPrm':0,'CapInh':0,'CapBnd':0,'CapAmb':0,'NoNewPrivs':1})
        self.assertEqual((c['jail']['size_bytes'],c['jail']['nr_inodes']),(16*MIB,1024))
        self.assertEqual(c['jail']['mount_data'],'size=16M,nr_inodes=1024,mode=0700')
        cg=c['cgroups']
        self.assertEqual(cg['allocation'],{'memory.max':896*MIB,'memory.swap.max':0,'memory.oom.group':1,'pids.max':32,'cpu.max':'100000 100000','direct_tasks':False})
        self.assertEqual(cg['relay'],{'memory.max':16*MIB,'pids.max':4,'cpu.max':'5000 100000'})
        self.assertEqual(cg['vm/console'],{'memory.max':4*MIB,'pids.max':2,'cpu.max':'5000 100000'})
        w=c['workers']
        self.assertEqual((w['L']['node_limit'],w['P']['node_limit'],w['P']['per_allocation'],w['S']['per_allocation'],w['R']['per_allocation'],w['D']['per_allocation'],w['M']['node_limit'],w['K']['node_limit']),(1,2,1,1,1,1,1,2))
        self.assertTrue(w['K']['reserved'])
        self.assertEqual(w['separate_executables'],[])
        h=c['handoff']
        self.assertEqual((h['version'],h['vmm_fd'],h['control_fd'],h['only_inherited_extra_fds'],h['close_on_vmm_exec'],h['jailer_exec_fd_min'],h['bootstrap_max_bytes'],h['stock_jailer_compatible']),(1,3,4,[3,4],[3,4],5,4096,False))
        self.assertEqual(c['executable']['roles'],list(p1.ROLES))
        self.assertIs(c['executable']['path_fallback'],False)
        self.assertEqual(c['executable']['ancestry']['parent_rename_authority'],'root-only')
        self.assertEqual(c['work']['loop']['offset'],0)
        self.assertIs(c['work']['loop']['regular_file_fallback'],False)
        self.assertEqual((c['sessions_per_vm'],c['persistent_inner_sandboxes'],c['warm_pool'],c['interruption']),(1,1,0,'terminate-vm-after-dispatch'))
        self.assertEqual(sorted(c['substitutions']),sorted(['instance_id','allocation_id','sandbox_id','boot_nonce','uid','gid','relay_uid','relay_gid','cid','work_uuid','inner_spec','executables']))


class Phase1bLegacyRefusalTests(Phase1bFixtureCase):
    def test_current_no_vsock_manifest_refused(self):
        legacy=(FIXTURES/'legacy-no-vsock-manifest.json').read_bytes()
        document=json.loads(legacy)
        self.assertEqual(document['schema'],1)
        self.assertIs(document['broker']['enabled'],False)
        self.assertEqual(document['launch_contract'],contract())
        self.assertNotIn('vsock',document['launch_contract']['profiles']['production']['firecracker'])
        for fixture_only in [True,False]:
            with self.assertRaisesRegex(ValueError,'legacy no-vsock is refused'):
                p1.verify_manifest(legacy,p1.digest(legacy),fixture_only=fixture_only)
        # A schema number or a grafted device cannot launder the legacy contract.
        for forged in [{**document,'schema':2},{**document,'schema':True}]:
            raw=json.dumps(forged).encode()
            with self.assertRaises(ValueError): p1.verify_manifest(raw,p1.digest(raw),fixture_only=True)
        graft=copy.deepcopy(document); graft['schema']=2
        graft['launch_contract']['profiles']['production']['firecracker']['vsock']={'guest_cid':3,'uds_path':'/run/vsock.sock'}
        raw=json.dumps(graft).encode()
        with self.assertRaises(ValueError): p1.verify_manifest(raw,p1.digest(raw),fixture_only=True)

    def test_real_legacy_manifest_refused_when_present(self):
        candidates=[ROOT.parent/'kiln-guest/dist/bundle-a/manifest.json',Path.home()/'kiln-guest-build/bundle-a/manifest.json',ROOT.parent/'bundle-a/manifest.json']
        found=[path for path in candidates if path.exists()]
        if not found: self.skipTest('legacy bundle not on this machine')
        raw=found[0].read_bytes()
        self.assertEqual(p1.digest(raw),'e855fbee1914cc6ea5e57a1250610e128412c85a905c94a48fb54afdaa47f3d3')
        self.assertGreater(len(raw),p1.MAX_MANIFEST)
        with self.assertRaisesRegex(ValueError,'exceeds 4 MiB'):
            p1.verify_manifest(raw,p1.digest(raw),fixture_only=True)

    def test_schema1_entry_points_refuse_phase1b_selection(self):
        manifest={'launch_contract':contract()}; entry=contract()['profiles']['production']
        for call in [lambda:verify_launch(manifest,entry['firecracker'],entry['jailer'],PHASE1B_PROFILE),
                     lambda:profile(manifest,PHASE1B_PROFILE),
                     lambda:verify_jailer_argv(manifest,entry['firecracker'],['j','--','x'],PHASE1B_PROFILE,expected_jailer='j',expected_exec='e',expected_base='b')]:
            with self.assertRaisesRegex(ValueError,'requires an approved schema 2'): call()
        self.assertEqual(profile(manifest,'production')['firecracker'],entry['firecracker'])

    def test_builder_refuses_profile_without_artifacts(self):
        result=sp.run([sys.executable,str(ROOT/'scripts/build.py'),'build','--profile',PHASE1B_PROFILE,'--cache','/nonexistent','--work','/nonexistent/w','--out','/nonexistent/o'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('reviewed-patched-jailer',result.stderr)
        with self.assertRaisesRegex(ValueError,'unavailable'): p1.refuse_build()

    def test_verify_cli_selection(self):
        verify=ROOT/'scripts/verify.py'
        plain=sp.run([sys.executable,str(verify),str(FIXTURES/'bundle')],capture_output=True,text=True)
        self.assertNotEqual(plain.returncode,0); self.assertIn('production is disabled',plain.stderr)
        ok=sp.run([sys.executable,str(verify),'--phase1b-fixture',self.approved,str(FIXTURES/'bundle'),str(FIXTURES/'executables')],capture_output=True,text=True)
        self.assertEqual(ok.returncode,0,ok.stderr)
        self.assertIs(json.loads(ok.stdout)['deployment_approved'],False)
        wrong=sp.run([sys.executable,str(verify),'--phase1b-fixture','00'*32,str(FIXTURES/'bundle'),str(FIXTURES/'executables')],capture_output=True,text=True)
        self.assertNotEqual(wrong.returncode,0)

    def test_init_keeps_broker_disabled_and_markers_diagnostic(self):
        source=(ROOT/'src/init.c').read_text()
        self.assertNotIn('AF_VSOCK',source)
        self.assertNotIn('/dev/vdc',source)
        self.assertIn('Phase 1b broker hook: disabled',source)
        self.assertRegex(source,r'Schema 1 benchmark label[^/]*\*/\n\s*puts\("KG_FIRST_COMMAND"\)')
        self.assertRegex(source,r'Schema 1 diagnostic[^/]*\*/\n\s*puts\("KG_READY"\)')


class Phase1bBundleFileTests(Phase1bFixtureCase):
    def refused(self,bundle,executables,approved=None):
        with self.assertRaises((ValueError,OSError)):
            p1.verify_bundle(bundle,approved or self.approved,executables,fixture_only=True)

    def tree(self,edit):
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            p1.verify_bundle(bundle,self.approved,executables,fixture_only=True)
            edit(bundle,executables)
            self.refused(bundle,executables)

    def test_extra_missing_renamed(self):
        for edit in [lambda b,e:(b/'debug').write_bytes(b'x'),lambda b,e:(e/'wrapper').write_bytes(b'x'),
                     lambda b,e:(b/'kiln').unlink(),lambda b,e:(e/'jailer').unlink(),
                     lambda b,e:(b/'kiln').rename(b/'kiln2'),lambda b,e:(e/'jailer').rename(e/'firejail'),
                     lambda b,e:(b/'manifest.json').unlink()]:
            self.tree(edit)

    def test_each_artifact_corruption_and_size(self):
        for directory,names in [('bundle',p1.ARTIFACTS),('executables',p1.ROLES)]:
            for name in names:
                def same_size(b,e,directory=directory,name=name):
                    path=(b if directory=='bundle' else e)/name
                    data=bytearray(path.read_bytes()); data[-1]^=1; path.write_bytes(data)
                def longer(b,e,directory=directory,name=name):
                    path=(b if directory=='bundle' else e)/name
                    path.write_bytes(path.read_bytes()+b'x')
                self.tree(same_size); self.tree(longer)

    def test_links_and_non_regular_entries(self):
        def symlink(b,e): (b/'Image').unlink(); (b/'Image').symlink_to(FIXTURES/'bundle/Image')
        def executable_symlink(b,e): (e/'jailer').unlink(); (e/'jailer').symlink_to(FIXTURES/'executables/jailer')
        def hardlink(b,e): os.link(b/'kiln',b.parent/'cached-kiln')
        def executable_hardlink(b,e): os.link(e/'firecracker',b.parent/'cached-vmm')
        def fifo(b,e): (b/'kernel.config').unlink(); os.mkfifo(b/'kernel.config')
        def directory(b,e): (e/'mkfs.xfs').unlink(); (e/'mkfs.xfs').mkdir()
        def manifest_symlink(b,e): (b/'manifest.json').unlink(); (b/'manifest.json').symlink_to(FIXTURES/'bundle/manifest.json')
        for edit in [symlink,executable_symlink,hardlink,executable_hardlink,fifo,directory,manifest_symlink]:
            self.tree(edit)
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            alias=Path(d)/'alias'; alias.symlink_to(bundle)
            self.refused(alias,executables)

    def test_oversized_manifest_refused_before_read(self):
        with tempfile.TemporaryDirectory() as d:
            bundle,executables=self.bundle_dir(d)
            with (bundle/'manifest.json').open('wb') as f: f.truncate(p1.MAX_MANIFEST+1)
            with self.assertRaisesRegex(ValueError,'exceeds size limit'):
                p1.verify_bundle(bundle,self.approved,executables,fixture_only=True)

    def test_static_elf_closure(self):
        for role in p1.ROLES: p1.verify_static_elf((FIXTURES/'executables'/role).read_bytes())
        elf=(FIXTURES/'executables/jailer').read_bytes()
        def segment_type(kind):
            data=bytearray(elf); data[64:68]=struct.pack('<I',kind); return bytes(data)
        needed=bytearray(segment_type(2)+struct.pack('<qQ',1,0)+struct.pack('<qQ',0,0))
        needed[64+8:64+16]=struct.pack('<Q',len(elf)); needed[64+32:64+40]=struct.pack('<Q',32)
        pie_no_needed=bytearray(segment_type(2)+struct.pack('<qQ',0,0))
        pie_no_needed[64+8:64+16]=struct.pack('<Q',len(elf)); pie_no_needed[64+32:64+40]=struct.pack('<Q',16)
        p1.verify_static_elf(bytes(pie_no_needed))
        for data,reason in [(b'#!/bin/sh\n'+bytes(64),'not a little-endian'),(segment_type(3),'loader'),(bytes(needed),'library'),
                            (elf[:18]+struct.pack('<H',62)+elf[20:],'not an aarch64'),(elf[:90],'truncated'),(elf[:40],'not a little-endian')]:
            with self.assertRaisesRegex(ValueError,reason): p1.verify_static_elf(data)


class Phase1bPlanTests(Phase1bFixtureCase):
    def test_golden_plans(self):
        p1.verify_plan(self.raw,self.approved,self.subs,self.plan,fixture_only=True)
        p1.verify_plan(self.raw,self.approved,load('substitutions-equal-ids.json'),load('plan-equal-ids.json'),fixture_only=True)
        digests=load('digests.json')
        self.assertEqual(p1.launch_digest(self.plan),digests['launch_sha256'])
        self.assertEqual(p1.plan_digest(self.plan),digests['plan_sha256'])
        with self.assertRaisesRegex(ValueError,'production disabled'): p1.plan(self.raw,self.approved,self.subs)

    def test_every_plan_leaf_refused(self):
        count=0
        for path,value in leaves(self.plan):
            if not path: continue
            for replacement in [changed(value),MISSING]:
                with self.assertRaises(ValueError,msg=(path,replacement)):
                    p1.verify_plan(self.raw,self.approved,self.subs,mutated(self.plan,path,replacement),fixture_only=True)
                count+=1
        self.assertGreater(count,500)

    def test_exact_argv_paths_and_resources(self):
        launch=self.plan['launch']; A='2b'*16; I='1a'*16
        pins=self.manifest['executables']
        jailer='/opt/kilnd/exec/sha256/'+pins['jailer']['sha256']+'/jailer'
        vmm='/opt/kilnd/exec/sha256/'+pins['firecracker']['sha256']+'/firecracker'
        self.assertEqual(launch['jailer_argv'],[jailer,'--id','fc-'+A,'--exec-file',vmm,'--uid','300001','--gid','300002',
            '--chroot-base-dir','/var/lib/kilnd-helper/jails','--cgroup-version','2',
            '--parent-cgroup',f'kilnd-firecracker/{I}/fc-{A}/vm/vmm','--new-pid-ns','--resource-limit','no-file=256',
            '--','--no-api','--config-file','/config.json'])
        self.assertEqual(launch['formatter_argv'],['/opt/kilnd/exec/sha256/'+pins['mkfs.xfs']['sha256']+'/mkfs.xfs','-q','-f','-K','-m',
            'uuid=51b8e65e-23b9-4eba-a21c-7c1cce2c5f94',launch['work_backing_path']])
        self.assertEqual(launch['jail_root'],f'/var/lib/kilnd-helper/jails/firecracker/fc-{A}/root')
        self.assertEqual(launch['cgroup'],f'kilnd-firecracker/{I}/fc-{A}')
        self.assertEqual(launch['firecracker']['vsock'],{'guest_cid':5253,'uds_path':'/run/vsock.sock'})
        self.assertLess(len(launch['vsock_host_path'].encode()),108)
        self.assertEqual(launch['reservation'],{'memory_bytes':896*MIB,'disk_bytes':1408*MIB,'pids':192,'host_pids':32,'host_cpu_millis':1000,'virtual_cpu_slots':1})
        self.assertEqual(launch['work_bytes'],1280*MIB)
        recipe=launch['resource_recipe']
        self.assertEqual(recipe['work']['loop']['size_limit'],1280*MIB)
        self.assertEqual(recipe['work']['loop']['owner'],[300001,300002])
        self.assertEqual((recipe['vmm_credentials']['uid'],recipe['vmm_credentials']['gid']),(300001,300002))
        self.assertEqual((recipe['relay_credentials']['uid'],recipe['relay_credentials']['gid']),(300003,300004))

    def test_work_disk_formula(self):
        for inner,expected in [(1,512),(256*MIB,512),(256*MIB+1,576),(320*MIB,576),(320*MIB+1,640),(1024*MIB,1280)]:
            spec=mutated(self.subs,('inner_spec','disk_bytes'),inner)
            self.assertEqual(self.prepared(spec)['launch']['work_bytes'],expected*MIB,inner)
            self.assertEqual(self.prepared(spec)['launch']['reservation']['disk_bytes'],(expected+128)*MIB)
        for inner in [0,2**64,-1,True,'1']:
            with self.assertRaises(ValueError): self.prepared(mutated(self.subs,('inner_spec','disk_bytes'),inner))
        with self.assertRaisesRegex(ValueError,'exceeds u64'):
            self.prepared(mutated(self.subs,('inner_spec','disk_bytes'),2**64-1))

    def test_uid_gid_are_separate_typed_substitutions(self):
        self.assertNotEqual(self.subs['uid']['value'],self.subs['gid']['value'])
        equal=load('substitutions-equal-ids.json')
        self.assertEqual(equal['uid']['value'],equal['gid']['value'])
        self.assertEqual(load('plan-equal-ids.json')['launch']['jailer_argv'][5:9],['--uid','300005','--gid','300005'])
        for name,kind in [('uid','VmmGid'),('gid','VmmUid'),('relay_uid','VmmUid'),('relay_gid','VmmGid'),('uid','RelayUid')]:
            with self.assertRaisesRegex(ValueError,'not interchangeable'):
                self.prepared(mutated(self.subs,(name,'kind'),kind))
        swapped=mutated(mutated(self.subs,('uid',),self.subs['gid']),('gid',),self.subs['uid'])
        with self.assertRaises(ValueError): self.prepared(swapped)
        collapsed=copy.deepcopy(self.plan); collapsed['launch']['jailer_argv'][8]=collapsed['launch']['jailer_argv'][6]
        with self.assertRaises(ValueError): p1.verify_plan(self.raw,self.approved,self.subs,collapsed,fixture_only=True)

    def test_every_substitution_rejects_bad_values(self):
        H16='ab'*8
        table={'instance_id':['ab',H16,'AB'*16,'zz'*16,'ab'*16+'\n',1,None],
               'allocation_id':['ab',H16,'AB'*16,'ab'*17,None],
               'sandbox_id':[H16,'sb-'+'ab'*7,'ex-'+H16,'sb-'+'AB'*8,'sb-'+H16+'\n',1],
               'boot_nonce':['ab'*31,'ab'*33,'AB'*32,None],
               'cid':[2,0,-1,65536,True,'3',None],
               'work_uuid':['51b8e65e-23b9-1eba-a21c-7c1cce2c5f94','51B8E65E-23B9-4EBA-A21C-7C1CCE2C5F94','51b8e65e23b94ebaa21c7c1cce2c5f94','x',None,1],
               'uid':[{'kind':'VmmUid','value':v} for v in [299999,365536,0,True,'300001']]+[300001,{'kind':'VmmUid','value':300001,'x':1}],
               'gid':[{'kind':'VmmGid','value':v} for v in [299999,365536,0,True]]+[300002],
               'relay_uid':[{'kind':'RelayUid','value':v} for v in [299999,300001]],
               'relay_gid':[{'kind':'RelayGid','value':v} for v in [365536,300002]]}
        for name,values in table.items():
            for value in values:
                with self.assertRaises(ValueError,msg=(name,value)): self.prepared(mutated(self.subs,(name,),value))
        for name in self.subs:
            with self.assertRaises(ValueError,msg=name): self.prepared(mutated(self.subs,(name,)))
        with self.assertRaises(ValueError): self.prepared({**self.subs,'kernel_args':'x'})
        for boundary in [300000,365535]:
            self.prepared(mutated(self.subs,('uid','value'),boundary))
        for cid in [3,65535]: self.prepared(mutated(self.subs,('cid',),cid))

    def test_inner_spec_is_validated_not_clamped(self):
        spec={'image':['ubuntu','','/kernel',1],'memory_bytes':[536870913,0,True,'1'],'cpu_millis':[1001,0],'pids':[0,2**32],
              'network':['full',{'allow':['1.1.1.1']},None],'read_only_root':[1,None],
              'writable_paths':[['/a'],None]}
        for name,values in spec.items():
            for value in values:
                with self.assertRaises(ValueError,msg=(name,value)): self.prepared(mutated(self.subs,('inner_spec',name),value))
        read_only=mutated(self.subs,('inner_spec','read_only_root'),True)
        for paths in [['/'],['a'],['/a/../b'],['/a/./b'],['/a//b'],['/a/'],['/a\nb'],['/a\x7fb'],['/a\u0085b'],['/a','/a'],['/'+'a'*1024],
                      ['/p%d'%i for i in range(17)],[1]]:
            with self.assertRaises(ValueError,msg=paths): self.prepared(mutated(read_only,('inner_spec','writable_paths'),paths))
        for paths in [['/data'],['/workspace/雪'],['/a/-flag'],['/'+'a'*1023],['/p%d'%i for i in range(16)]]:
            self.prepared(mutated(read_only,('inner_spec','writable_paths'),paths))
        with self.assertRaises(ValueError): self.prepared(mutated(self.subs,('inner_spec','labels'),{'a':'b'}))
        self.assertEqual(self.prepared(mutated(self.subs,('inner_spec','memory_bytes'),1))['launch']['reservation']['memory_bytes'],896*MIB)

    def test_executable_identity_vector(self):
        vector=('executables',)
        for role in p1.ROLES:
            for field,value in [('sha256','00'*32),('bytes',1),('st_dev',0),('st_ino',0),('installation_generation',0),
                                ('st_ino',True),('st_dev','1'),('st_ino',2**64),('role','wrapper')]:
                with self.assertRaises(ValueError,msg=(role,field)): self.prepared(mutated(self.subs,vector+(role,field),value))
            with self.assertRaises(ValueError): self.prepared(mutated(self.subs,vector+(role,'format'),'static-elf'))
            with self.assertRaises(ValueError): self.prepared(mutated(self.subs,vector+(role,)))
        alias=mutated(self.subs,vector+('firecracker','st_ino'),self.subs['executables']['jailer']['st_ino'])
        with self.assertRaisesRegex(ValueError,'alias one inode'): self.prepared(alias)
        with self.assertRaises(ValueError): self.prepared(mutated(self.subs,vector+('wrapper',),self.subs['executables']['jailer']))
        # Node-local inode values enter the plan; a different inode is a different plan.
        moved=mutated(self.subs,vector+('jailer','st_ino'),9999)
        self.assertNotEqual(p1.plan_digest(self.prepared(moved)),p1.plan_digest(self.plan))

    def test_replacement_cases_compare_actual_identity(self):
        cases=load('replacement-cases.json')
        self.assertEqual({case['role'] for case in cases['cases']},set(p1.ROLES))
        for case in cases['cases']:
            if case['accept']:
                p1.verify_observation(case['expected'],case['observed'])
            else:
                with self.assertRaisesRegex(ValueError,'disagrees with retained FD',msg=case['race']):
                    p1.verify_observation(case['expected'],case['observed'])
        expected=self.subs['executables']['firecracker']
        observed={k:expected[k] for k in ['role','st_dev','st_ino','bytes','sha256']}
        for field,value in [('st_dev',1.0),('st_ino',str(expected['st_ino'])),('role','jailer')]:
            with self.assertRaises(ValueError): p1.verify_observation(expected,{**observed,field:value})
        with self.assertRaises(ValueError): p1.verify_observation(expected,{**observed,'extra':1})
        with self.assertRaises(ValueError): p1.verify_observation(expected,{k:v for k,v in observed.items() if k!='st_dev'})
        p1.verify_reopen(expected,copy.deepcopy(expected))
        for field,value in [('st_ino',1),('st_dev',1),('installation_generation',2),('sha256','00'*32),('bytes',1)]:
            with self.assertRaises(ValueError): p1.verify_reopen(expected,{**expected,field:value})

    def test_serialized_config(self):
        config=self.plan['launch']['firecracker']
        p1.verify_config_bytes(self.plan,json.dumps(config,indent=1).encode())
        shuffled=dict(reversed(list(config.items())))
        p1.verify_config_bytes(self.plan,json.dumps(shuffled).encode())
        drives=copy.deepcopy(config); drives['drives'].reverse()
        nic={**config,'network-interfaces':[]}
        for raw in [json.dumps(drives).encode(),json.dumps(nic).encode(),b'{"vsock":{},"vsock":{}}',
                    json.dumps(config).replace('"vcpu_count": 1','"vcpu_count": 1, "vcpu_count": 2').encode()]:
            with self.assertRaises(ValueError): p1.verify_config_bytes(self.plan,raw)

    def test_vmm_argv_timing_exception(self):
        argv=load('vmm-argv.json')
        p1.verify_vmm_argv(self.plan,argv)
        for index in [4,6,8]:
            for value in ['0','1',str(2**64-1)]:
                changed_argv=list(argv); changed_argv[index]=value; p1.verify_vmm_argv(self.plan,changed_argv)
            for value in ['-1','01','1.0','0x10','',' 1',str(2**64),'١',1,None]:
                changed_argv=list(argv); changed_argv[index]=value
                with self.assertRaises(ValueError,msg=value): p1.verify_vmm_argv(self.plan,changed_argv)
        swapped=list(argv); swapped[3],swapped[5]=swapped[5],swapped[3]
        for bad in [swapped,argv[:-1],argv+['--seccomp-level'],['/bin/sh']+argv[1:],argv[:1]+['--id','fc-'+'00'*16]+argv[3:],
                    argv[:9]+['--api-sock','/api.sock']+argv[11:],argv[:9]+['--no-seccomp']+argv[10:],tuple(argv),None]:
            with self.assertRaises(ValueError,msg=bad): p1.verify_vmm_argv(self.plan,bad)
        # Timing values are excluded from the semantic digest; the plan holds no timing slot.
        self.assertEqual(self.plan['launch']['vmm_argv_semantic'],['/firecracker','--id','fc-'+'2b'*16,'--no-api','--config-file','/config.json'])

    def test_vmm_status_masks(self):
        status=(FIXTURES/'vmm-status.txt').read_text()
        p1.verify_vmm_status(self.plan,status)
        for name in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']:
            with self.assertRaisesRegex(ValueError,name):
                p1.verify_vmm_status(self.plan,re.sub(name+r':\t0+',name+':\t0000000000000001',status))
            with self.assertRaisesRegex(ValueError,name):
                p1.verify_vmm_status(self.plan,re.sub(name+r':.*\n','',status))
        for old,new in [('Groups:\t','Groups:\t0'),('NoNewPrivs:\t1','NoNewPrivs:\t0'),('Seccomp:\t2','Seccomp:\t0'),
                        ('Uid:\t300001\t300001\t300001\t300001','Uid:\t300002\t300002\t300002\t300002'),
                        ('Gid:\t300002\t300002\t300002\t300002','Gid:\t300001\t300001\t300001\t300001'),
                        ('Uid:\t300001\t300001\t300001\t300001','Uid:\t0\t300001\t300001\t300001'),
                        ('Gid:\t300002\t300002\t300002\t300002','Gid:\t300002\t300002\t0\t300002')]:
            self.assertNotEqual(status.replace(old,new),status)
            with self.assertRaises(ValueError,msg=new): p1.verify_vmm_status(self.plan,status.replace(old,new))
        with self.assertRaisesRegex(ValueError,'duplicate'): p1.verify_vmm_status(self.plan,status+'CapEff:\t0000000000000000\n')

    def test_bootstrap_record(self):
        golden=load('bootstrap.json')
        raw=p1.canonical(golden['record'])
        p1.verify_bootstrap(self.plan,golden['plan_generation'],golden['jail_root_identity'],raw)
        self.assertLessEqual(len(raw),4096)
        self.assertEqual(golden['record']['vmm_identity']['st_ino'],self.subs['executables']['firecracker']['st_ino'])
        self.assertEqual(golden['record']['exec_file_label'],self.plan['launch']['executable_paths']['firecracker'])
        for path,value in leaves(golden['record']):
            if path:
                with self.assertRaises(ValueError,msg=path):
                    p1.verify_bootstrap(self.plan,1,golden['jail_root_identity'],p1.canonical(mutated(golden['record'],path,changed(value))))
        with self.assertRaises(ValueError): p1.verify_bootstrap(self.plan,2,golden['jail_root_identity'],raw)
        with self.assertRaises(ValueError): p1.bootstrap_record(self.plan,0,golden['jail_root_identity'])
        with self.assertRaises(ValueError): p1.bootstrap_record(self.plan,1,{**golden['jail_root_identity'],'st_ino':0})


class Phase1bIdentityTests(Phase1bFixtureCase):
    def block(self): return (FIXTURES/'identity.bin').read_bytes()

    def test_golden_binds_every_field(self):
        record=p1.read_identity(self.block())
        p1.verify_identity(self.block(),self.plan)
        self.assertEqual(self.block(),p1.identity_block(self.plan))
        self.assertEqual(len(self.block()),4096)
        self.assertEqual(self.block()[:4],b'KID1')
        self.assertEqual(record['manifest_sha256'],self.approved)
        self.assertEqual(record['launch_sha256'],p1.launch_digest(self.plan))
        self.assertEqual(record['inner_spec_sha256'],p1.digest(p1.canonical(self.subs['inner_spec'])))
        for name in ['instance_id','allocation_id','sandbox_id','boot_nonce','work_uuid']:
            self.assertEqual(record[name],self.subs[name])
        self.assertEqual(sorted(record),sorted(p1.contract()['identity']['fields']))

    def test_every_byte_matters(self):
        block=self.block()
        for index in range(len(block)):
            damaged=bytearray(block); damaged[index]^=1
            with self.assertRaises(ValueError,msg=index): p1.verify_identity(bytes(damaged),self.plan)

    def test_framing(self):
        record=json.loads(self.block()[8:8+struct.unpack('>I',self.block()[4:8])[0]])
        canonical=p1.canonical(record)
        def framed(payload,length=None,pad=None):
            data=b'KID1'+struct.pack('>I',len(payload) if length is None else length)+payload
            return data+bytes(4096-len(data)) if pad is None else data+pad
        p1.read_identity(framed(canonical))
        for block,reason in [(framed(canonical)[:4095],'framing'),(framed(canonical)+b'\0','framing'),(b'KID2'+framed(canonical)[4:],'framing'),
                (framed(canonical,0),'length'),(framed(canonical,4089),'length'),(framed(canonical,len(canonical)-1),'JSON|padding|length'),
                (framed(canonical,len(canonical)+1),'JSON|canonical|invalid'),
                (framed(canonical[:-1]+b' }'),'canonical'),(framed(json.dumps(record,indent=1).encode()),'canonical'),
                (framed(p1.canonical({**record,'extra':1})),'fields'),(framed(p1.canonical({k:v for k,v in record.items() if k!='work_uuid'})),'fields'),
                (framed(b'{"a":1,"a":2}'),'duplicate|fields'),(framed(canonical[:-1]+b',"boot_nonce":"00"}'),'duplicate')]:
            with self.assertRaisesRegex(ValueError,reason,msg=block[:32]): p1.read_identity(block)
        tail=bytearray(framed(canonical)); tail[-1]=1
        with self.assertRaisesRegex(ValueError,'padding'): p1.read_identity(bytes(tail))
        for name,value in [('instance_id','x'),('allocation_id',1),('sandbox_id','ab'),('boot_nonce','AB'*32),('manifest_sha256','0'),
                           ('launch_sha256',None),('inner_spec_sha256','0'*63),('work_uuid','x')]:
            with self.assertRaises(ValueError,msg=name): p1.read_identity(framed(p1.canonical({**record,name:value})))

    def test_launch_digest_excludes_block_but_covers_identity_drive(self):
        other=self.prepared(mutated(self.subs,('boot_nonce',),'5e'*32))
        self.assertEqual(p1.launch_digest(other),p1.launch_digest(self.plan))
        self.assertNotEqual(p1.identity_block(other),self.block())
        with self.assertRaises(ValueError): p1.verify_identity(self.block(),other)
        self.assertNotIn(self.block()[8:40].decode(),json.dumps(self.plan))
        dropped=copy.deepcopy(self.plan); del dropped['launch']['firecracker']['drives'][2]
        self.assertNotEqual(p1.launch_digest(dropped),p1.launch_digest(self.plan))
        for mutated_plan in [mutated(self.plan,('launch','jailer_argv',6),'0'),mutated(self.plan,('launch','resource_recipe','jail','size_bytes'),1)]:
            self.assertNotEqual(p1.launch_digest(mutated_plan),p1.launch_digest(self.plan))


class Phase1bEvidenceTests(unittest.TestCase):
    """Checked-in VM evidence. results/ is excluded from staged sources, so skip there."""
    def evidence(self,name):
        path=ROOT/'results/phase1b-b1'/name
        if not path.exists(): self.skipTest('results are not staged into the VM')
        return json.loads(path.read_text())

    def test_measured_suffix(self):
        pin=p1.inputs_pin()['suffix_evidence']
        self.assertEqual(pin['path'],'results/phase1b-b1/suffix-probe.json')
        topology=self.evidence('suffix-probe.json')['topologies']['offline-768-v1-three-drives-vsock']
        self.assertEqual(p1.digest((ROOT/pin['path']).read_bytes()),pin['sha256'])
        self.assertEqual(topology['drives'],['rootfs','work','identity'])
        self.assertTrue(topology['vsock'])
        self.assertEqual(topology['observed_suffix'],p1.contract()['firecracker_cmdline_suffix'])
        self.assertEqual(topology['test_mode_observed_cmdline'],CMDLINE+' kiln.test=1'+FC_SUFFIX)
        self.assertEqual(topology['legacy_init_verdict_test_mode'],'PASS')
        self.assertEqual(topology['legacy_init_verdict_production_args'],'PASS')

    def test_recorded_retained_fd_races(self):
        check_races(self,self.evidence('retained-fd.json'))


def check_races(case,result):
    """Pass only on the actual executed tuple; argv and earlier hashes never suffice."""
    records=result['records']
    case.assertEqual(len(records),len(p1.ROLES)*len(CASES))
    case.assertEqual({(r['role'],r['race']) for r in records},{(role,race) for role in p1.ROLES for race in CASES})
    for r in records:
        with case.subTest(role=r['role'],race=r['race']):
            expected=r['expected']; case.assertEqual(expected['role'],r['role'])
            if r['race']=='closed-fd-reused':
                case.assertEqual(r['verdict'],'refused')
                case.assertIsNotNone(r['reused_fd_preexec_refusal'])
                case.assertIsNotNone(r['reused_fd_observation_refusal'])
                case.assertTrue(r['digest_matches_prior_hash'])
                case.assertNotEqual(r['reused_fd_observed']['st_ino'],expected['st_ino'])
                continue
            case.assertEqual(r['verdict'],'retained-inode-ran')
            for name in ['st_dev','st_ino','bytes','sha256','role']:
                case.assertEqual(r['observed'][name],expected[name])
            case.assertTrue(r['handoff_fds_exact'])
            case.assertEqual(r['surviving_fds'],[0,1,2,3,4] if r['role']=='jailer' else [0,1,2])
            case.assertEqual(r['actual_argv'],r['argv'])
            case.assertEqual(r['boundary'],{'jailer':'before-S-exec-J','firecracker':'before-J-exec-V','mkfs.xfs':'before-formatter-exec','kilnd-helper':'before-worker-exec'}[r['role']])
            case.assertIsNotNone(r['control_refusal'])
            case.assertTrue(r['control_argv_matches'])
            case.assertNotEqual(r['control_observed']['st_ino'],expected['st_ino'])
            if r['race']=='source-parent':
                case.assertEqual(r['attacker_source_parent_exit'],0)
                case.assertFalse(r['control_digest_matches_prior_hash'])
                case.assertIsNone(r['protected_reopen_refusal'])
            else:
                case.assertIsNotNone(r['protected_reopen_refusal'])
            if r['race'] in ('installed-identical-bytes','installed-parent'):
                case.assertTrue(r['control_digest_matches_prior_hash'])
    for role,attempts in result['unprivileged_rename_exit_codes'].items():
        case.assertGreaterEqual(len(attempts),4)
        for path,code in attempts.items(): case.assertEqual(code,1,(role,path))


LINUX_ROOT=sys.platform=='linux' and os.uname().machine=='aarch64' and os.geteuid()==0

@unittest.skipUnless(LINUX_ROOT,'requires Linux aarch64 root and a privilege drop')
class Phase1bRetainedFdTests(unittest.TestCase):
    def setUp(self):
        import exec_identity_fixture as harness
        self.harness=harness
        self.manifest=load('bundle/manifest.json')
        fd=trusted_directory(TRUST_ROOT,create=True); os.close(fd)
        self.private=Path(tempfile.mkdtemp(prefix='b1-ancestry-',dir=TRUST_ROOT))
        self.addCleanup(shutil.rmtree,self.private)
        self.data=(FIXTURES/'executables/jailer').read_bytes()
        self.pin=self.manifest['executables']['jailer']

    def install(self,store=None):
        store=store or self.private/'store'
        source=self.private/'source'; source.write_bytes(self.data)
        fd=os.open(source,os.O_RDONLY|os.O_CLOEXEC)
        try: return install_executable(fd,store,'jailer',self.pin)
        finally: os.close(fd); source.unlink()

    def open(self,path): return open_executable(path,'jailer',self.pin,1)

    def test_all_roles_and_races(self):
        check_races(self,self.harness.run_all())

    def test_retained_fd_exec_needs_no_path_or_proc(self):
        path=self.install(); fd,expected=self.open(path); fd=self.harness.high_fd(fd)
        self.addCleanup(os.close,fd)
        path.unlink(); path.parent.rmdir()
        observed,fds,argv=self.harness.observe(self.harness.spawn(['/display-name-only'],exec_fd=fd),'jailer')
        p1.verify_observation(expected,observed)
        self.assertEqual(argv,['/display-name-only'])
        self.assertEqual(sorted(fds),[0,1,2])

    def test_installed_object_requirements(self):
        path=self.install(); directory=path.parent
        fd,expected=self.open(path); os.close(fd)
        self.assertEqual(expected['bytes'],self.pin['bytes'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o555)
        self.assertEqual(path.stat().st_nlink,1)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        self.assertEqual(install_executable(os.open(FIXTURES/'executables/jailer',os.O_RDONLY),self.private/'store','jailer',self.pin),path,'an existing matching object stays')
        for mode in [0o755,0o4555,0o2555,0o444]:
            path.chmod(mode)
            with self.assertRaises(ValueError,msg=oct(mode)): self.open(path)
        path.chmod(0o555)
        os.chown(path,10001,0)
        with self.assertRaises(ValueError): self.open(path)
        os.chown(path,0,0)
        link=directory/'alias'; os.link(path,link)
        with self.assertRaises(ValueError): self.open(path)
        link.unlink()
        cap=struct.pack('<IIIII',0x02000001,1,0,0,0)
        os.setxattr(path,'security.capability',cap)
        with self.assertRaisesRegex(ValueError,'file capabilities'): self.open(path)
        os.removexattr(path,'security.capability')
        self.open(path)
        symlink=directory/'link'; symlink.symlink_to(path)
        with self.assertRaises(OSError): self.open(symlink)
        symlink.unlink()
        fifo=directory/'fifo'; os.mkfifo(fifo,0o555)
        with self.assertRaises(ValueError): open_executable(fifo,'jailer',self.pin,1)
        fifo.unlink()
        other=directory/'script'; other.write_bytes(b'#!/bin/sh\n'+bytes(len(self.data)-10)); other.chmod(0o555)
        with self.assertRaises(ValueError): open_executable(other,'jailer',{**self.pin,'sha256':p1.digest(other.read_bytes())},1)

    def test_every_protected_ancestor_is_checked(self):
        path=self.install(); levels=[path.parent,path.parent.parent,self.private/'store']
        acl=lambda *entries: struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in entries)
        named=acl((1,7,0xffffffff),(2,7,10001),(4,5,0xffffffff),(0x10,5,0xffffffff),(0x20,5,0xffffffff))
        for level in levels:
            mode=stat.S_IMODE(level.stat().st_mode)
            for bad in [0o775,0o757,0o777,0o1777]:
                level.chmod(bad)
                with self.assertRaises(ValueError,msg=(level,oct(bad))): self.open(path)
            level.chmod(mode)
            os.chown(level,10001,0)
            with self.assertRaises(ValueError,msg=level): self.open(path)
            os.chown(level,0,0)
            for name in ['system.posix_acl_access','system.posix_acl_default']:
                os.setxattr(level,name,named)
                with self.assertRaisesRegex(ValueError,'ACL',msg=(level,name)): self.open(path)
                os.removexattr(level,name)
            os.chmod(level,mode)
            self.open(path)
        link=self.private/'store-link'; link.symlink_to(self.private/'store')
        with self.assertRaises(OSError): self.open(link/path.relative_to(self.private/'store'))
        # A parent owned by another user holds rename authority even over a root-owned child.
        shell=self.private/'unsafe'; shell.mkdir(); os.chown(shell,10001,10001); shell.chmod(0o755)
        with self.assertRaises(ValueError):
            protected_directory(shell/'child',create=False)

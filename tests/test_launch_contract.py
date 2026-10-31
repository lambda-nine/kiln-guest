"""KR-01: exact profiles and every security-relevant deviation fail closed."""
import copy
import unittest
from launch_contract import contract, verify_launch, verify_jailer_argv

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
        verify_jailer_argv(manifest,config,argv,'production')
        for changed in [argv+['--no-seccomp'],argv[:13]+['--daemonize']+argv[13:],
                        [s if i!=6 else '0' for i,s in enumerate(argv)]]:
            with self.assertRaises(ValueError): verify_jailer_argv(manifest,config,changed,'production')
        bad=copy.deepcopy(config); bad['machine-config']['vcpu_count']=True
        with self.assertRaises(ValueError): verify_launch(manifest,bad,contract()['profiles']['production']['jailer'])

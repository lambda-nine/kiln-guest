"""Canonical cold-boot contract. No unlisted device, flag or override is accepted.

Phase 1b must authenticate the manifest identity before using this contract.
Paths below are fixed names inside a fresh per-session jail, not shared disks.
"""
import copy
import json
import re

CMDLINE='console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3 randomize_kstack_offset=on'

FC_SUFFIX=' pci=off root=/dev/vda ro earlycon=uart,mmio,0x40002000'

def contract():
    profiles={}
    for name,suffix in [('production',''),('test-offline',' kiln.test=1'),('test-network',' kiln.test=1 kiln.net=1')]:
        config={'boot-source':{'kernel_image_path':'/kernel','boot_args':CMDLINE+suffix},
                'machine-config':{'vcpu_count':1,'mem_size_mib':768,'smt':False,
                                  'huge_pages':'Transparent','track_dirty_pages':False},
                'drives':[{'drive_id':'rootfs','path_on_host':'/rootfs','is_root_device':True,'is_read_only':True},
                          {'drive_id':'work','path_on_host':'/work','is_root_device':False,'is_read_only':False}]}
        if name=='test-network':
            config['network-interfaces']=[{'iface_id':'eth0','guest_mac':'06:00:ac:1e:63:02','host_dev_name':'kgtest0'}]
        profiles[name]={'firecracker':config,'jailer':{'uid':10000,'gid':10000,'cgroup_version':2,
            'seccomp':'default','parent_cgroup':None,'cgroups':[], 'new_pid_namespace':False,
            'daemonize':False,'resource_limits':[], 'api_socket':'/api.sock','config_file':'/config.json'}}
    return {'schema':1,'firecracker_cmdline_suffix':FC_SUFFIX,'boot':'cold-only','cpu_template':None,'snapshot_restore':False,
            'profiles':profiles}

def exact(a,b):
    return json.dumps(a,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(b,sort_keys=True,separators=(',',':'),allow_nan=False)

def verify_launch(manifest, config, jailer, profile='production'):
    expected=contract()
    if not exact(manifest.get('launch_contract'),expected):
        raise ValueError('manifest launch contract is missing or unsupported')
    if profile not in expected['profiles']:
        raise ValueError('unapproved launch profile')
    if not exact({'firecracker':config,'jailer':jailer},expected['profiles'][profile]):
        raise ValueError('launch deviates from approved contract')

def profile(manifest, name):
    entry=copy.deepcopy(contract()['profiles'][name])
    verify_launch(manifest,entry['firecracker'],entry['jailer'],name)
    return entry

def verify_jailer_argv(manifest, config, argv, profile_name, *, expected_jailer, expected_exec, expected_base):
    """Check the actual planned argument vector, not just a parallel settings map."""
    args=list(map(str,argv))[1:]
    try:
        boundary=args.index('--'); options=args[:boundary]; tail=args[boundary+1:]
    except ValueError: raise ValueError('jailer argument separator missing')
    allowed={'--id','--exec-file','--uid','--gid','--cgroup-version','--chroot-base-dir'}
    if len(options)!=2*len(allowed) or set(options[::2])!=allowed:
        raise ValueError('unapproved jailer flags')
    flags=dict(zip(options[::2],options[1::2]))
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',flags['--id']):
        raise ValueError('unsafe jailer id')
    if tail!=['--api-sock','/api.sock','--config-file','/config.json']:
        raise ValueError('unapproved Firecracker flags (seccomp must remain default)')
    if (str(argv[0])!=str(expected_jailer) or flags['--exec-file']!=str(expected_exec)
            or flags['--chroot-base-dir']!=str(expected_base)):
        raise ValueError('jailer executable or private root differs from verified launch')
    settings=copy.deepcopy(contract()['profiles'][profile_name]['jailer'])
    settings.update(uid=int(flags['--uid']),gid=int(flags['--gid']),cgroup_version=int(flags['--cgroup-version']))
    verify_launch(manifest,config,settings,profile_name)

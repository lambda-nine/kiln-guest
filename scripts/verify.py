#!/usr/bin/env python3
"""Verify bundle artifacts and compare independent manifest digests."""
import hashlib
import json
from pathlib import Path
import sys
from launch_contract import contract, exact, verify_phase1b_bundle

def verify(directory, allow_diagnostic=False):
    root=Path(directory)
    manifest=json.loads((root/'manifest.json').read_text())
    if manifest['schema']==2 and type(manifest['schema']) is int:
        raise ValueError('schema 2 needs its independent approval; production is disabled')
    if manifest['schema']!=1: raise ValueError('unknown manifest schema')
    if 'diagnostic_only' in manifest and not allow_diagnostic:
        raise ValueError('diagnostic bundle is not an acceptance build')
    if not allow_diagnostic and not exact(manifest.get('launch_contract'),contract()):
        raise ValueError('missing or unsupported launch contract')
    if set(manifest['artifacts'])!={'Image','kernel.config','kiln','rootfs.squashfs'}:
        raise ValueError('unexpected artifact set')
    for name, record in manifest['artifacts'].items():
        path=root/name
        if path.stat().st_size!=record['bytes']: raise ValueError(f'{name}: size mismatch')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
            raise ValueError(f'{name}: digest mismatch')
    return manifest

if __name__=='__main__':
    if sys.argv[1:2]==['--phase1b-fixture']:
        # Exercises the contract on test artifacts only; it can approve nothing.
        if len(sys.argv)!=5: raise SystemExit('usage: verify.py --phase1b-fixture APPROVED_SHA256 BUNDLE EXECUTABLES')
        print(json.dumps({'artifacts':verify_phase1b_bundle(sys.argv[3],sys.argv[2],sys.argv[4],fixture_only=True)['artifacts'],
                          'fixture_only':True,'deployment_approved':False},indent=2))
        raise SystemExit(0)
    manifests=[verify(d) for d in sys.argv[1:]]
    if not manifests: raise SystemExit('usage: verify.py BUNDLE [BUNDLE...]')
    if any(m!=manifests[0] for m in manifests[1:]): raise SystemExit('independent manifests differ')
    print(json.dumps({'reproducible':len(manifests)>1,'artifacts':manifests[0]['artifacts']},indent=2))

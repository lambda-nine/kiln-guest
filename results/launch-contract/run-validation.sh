#!/bin/sh
# Run from kiln-guest after the final full build pair. The wrapper owns the lock.
set -eu
python3 scripts/lima.py command 'set -e
cd ~/kiln-guest-build/repo
sudo python3 scripts/verify.py ../bundle-a ../bundle-b
for artifact in Image kernel.config kiln rootfs.squashfs manifest.json; do
    sudo cmp "../bundle-a/$artifact" "../bundle-b/$artifact"
    echo "BYTE_EQUAL $artifact"
done
sudo env PYTHONPATH=scripts python3 tests/runtime_negative.py ../bundle-a ../cache ../results/launch-contract/runtime-negative
sudo python3 tests/firecracker.py --bundle ../bundle-a --cache ../cache --out ../results-launch-contract
sudo du -sb ../cache
sudo lsattr ../cache/toolchain.squashfs
sha256sum ../bundle-a/manifest.json
'

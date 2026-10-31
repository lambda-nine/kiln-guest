"""KR-02: attacker-selected extractor/path and altered rootfs fail."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import build
from build_environment import FIXED_PATH, sha, verify_image

class BuildEnvironmentTests(unittest.TestCase):
    def test_attacker_selected_dpkg_deb_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'dpkg-deb'; fake.write_text('#!/bin/sh\nexit 99\n'); fake.chmod(0o755)
            with mock.patch.dict(os.environ,{'PATH':d+':'+FIXED_PATH}):
                with self.assertRaisesRegex(ValueError,'unapproved build PATH'): build.toolchain()

    def test_readonly_root_required(self):
        with mock.patch.dict(os.environ,{'PATH':FIXED_PATH}), mock.patch.object(build.os,'statvfs') as st:
            st.return_value.f_flag=0
            with self.assertRaisesRegex(ValueError,'read-only'): build.toolchain()

    def test_image_change_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/'toolchain.squashfs';image.write_bytes(b'approved rootfs')
            lock={'sha256':sha(image),'path':FIXED_PATH};verify_image(image,lock)
            image.write_bytes(b'attacker rootfs')
            with self.assertRaisesRegex(ValueError,'digest mismatch'): verify_image(image,lock)

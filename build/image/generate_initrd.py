#!/usr/bin/env python
#
# Copyright 2018 The Hafnium Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generate an initial RAM disk for the hypervisor.

Packages the VMs, initrds for the VMs and the list of secondary VMs (vms.txt)
into an initial RAM disk image.
"""

import argparse
import os
import shutil
import subprocess
import sys


def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--primary_vm", required=True)
    parser.add_argument("--primary_vm_initrd")
    parser.add_argument(
        "--secondary_vm",
        action="append",
        nargs=2,
        metavar=("NAME", "IMAGE"))
    parser.add_argument("--staging", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    staged_files = ["vmlinuz", "initrd.img"]

    # Create staging folder if needed.
    if not os.path.isdir(args.staging):
        os.makedirs(args.staging)

    # Prepare the manifest.
    if args.manifest:
        shutil.copyfile(args.manifest, os.path.join(args.staging, "manifest.dtb"))
        staged_files += ["manifest.dtb"]
    # Prepare the primary VM image.
    shutil.copyfile(args.primary_vm, os.path.join(args.staging, "vmlinuz"))
    # Prepare the primary VM's initrd.
    if args.primary_vm_initrd:
        shutil.copyfile(args.primary_vm_initrd, os.path.join(args.staging, "initrd.img"))
    else:
        open(os.path.join(args.staging, "initrd.img"), "w").close()
    # Prepare the secondary VMs.
    if args.secondary_vm:
        for vm in args.secondary_vm:
            (vm_name, vm_image) = vm
            staged_files.append(vm_name)
            shutil.copy(vm_image, os.path.join(args.staging, vm_name))
    # Package files into an initial RAM disk.
    with open(args.output, "w") as initrd:
        # Move into the staging directory so the file names taken by cpio don't
        # include the path.
        os.chdir(args.staging)
        cpio = subprocess.Popen(
            ["cpio", "--create"],
            stdin=subprocess.PIPE,
            stdout=initrd,
            stderr=subprocess.PIPE)
        cpio.communicate(input="\n".join(staged_files).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(Main())

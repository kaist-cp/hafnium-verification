/*
 * Copyright 2019 Sanguk Park
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use core::convert::TryInto;
use core::fmt::{self, Write};
use core::ptr;

use crate::fdt::*;
use crate::fdt_handler::*;
use crate::memiter::*;
use crate::types::*;

use arrayvec::ArrayVec;

/// "vm" + number + null terminator
const VM_NAME_BUF_SIZE: usize = 2 + 5 + 1;
const_assert!(MAX_VMS <= 99999);

#[derive(PartialEq, Debug)]
pub enum Error {
    CorruptedFdt,
    NoRootFdtNode,
    NoHypervisorFdtNode,
    ReservedVmId,
    NoPrimaryVm,
    TooManyVms,
    PropertyNotFound,
    MalformedString,
    MalformedInteger,
    IntegerOverflow,
}

impl Into<&'static str> for Error {
    fn into(self) -> &'static str {
        use Error::*;
        match self {
            CorruptedFdt => "Manifest failed FDT validation",
            NoRootFdtNode => "Could not find root node of manifest",
            NoHypervisorFdtNode => "Could not find \"hypervisor\" node in manifest",
            ReservedVmId => "Manifest defines a VM with a reserved ID",
            NoPrimaryVm => "Manifest does not contain a primary VM entry",
            TooManyVms => {
                "Manifest specifies more VMs than Hafnium has statically allocated space for"
            }
            PropertyNotFound => "Property not found",
            MalformedString => "Malformed string property",
            MalformedInteger => "Malformed integer property",
            IntegerOverflow => "Integer overflow",
        }
    }
}

/// Holds information about one of the VMs described in the manifest.
#[derive(Debug)]
pub struct ManifestVm {
    // Properties defined for both primary and secondary VMs.
    pub debug_name: MemIter,

    // Properties specific to secondary VMs.
    pub kernel_filename: MemIter,
    pub mem_size: u64,
    pub vcpu_count: spci_vcpu_count_t,
}

/// Hafnium manifest parsed from FDT.
#[derive(Debug)]
pub struct Manifest {
    pub vms: ArrayVec<[ManifestVm; MAX_VMS]>,
}

/// Generates a string with the two letters "vm" followed by an integer.
fn generate_vm_node_name<'a>(
    buf: &'a mut [u8; VM_NAME_BUF_SIZE],
    vm_id: spci_vm_id_t,
) -> &'a mut [u8] {
    struct BufWrite<'a> {
        buf: &'a mut [u8; VM_NAME_BUF_SIZE],
        size: usize,
    }

    impl<'a> Write for BufWrite<'a> {
        fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
            let dest = self
                .buf
                .get_mut(self.size..(self.size + s.len()))
                .ok_or(fmt::Error)?;
            dest.copy_from_slice(s.as_bytes());
            self.size += s.len();

            Ok(())
        }
    }

    let mut buf = BufWrite { buf, size: 0 };
    write!(buf, "vm{}\0", vm_id).unwrap();
    &mut buf.buf[..buf.size]
}

/// TODO(HfO2): This function is marked `inline(never)`, to prevent stack overflow. It is still
/// mysterious why inlining this function into ManifestVm::new makes stack overflow.
#[inline(never)]
fn read_string<'a>(node: &FdtNode<'a>, property: *const u8) -> Result<MemIter, Error> {
    let data = node
        .read_property(property)
        .map_err(|_| Error::PropertyNotFound)?;

    if data[data.len() - 1] != b'\0' {
        return Err(Error::MalformedString);
    }

    Ok(unsafe { MemIter::from_raw(data.as_ptr(), data.len() - 1) })
}

fn read_u64<'a>(node: &FdtNode<'a>, property: *const u8) -> Result<u64, Error> {
    let data = node
        .read_property(property)
        .map_err(|_| Error::PropertyNotFound)?;

    fdt_parse_number(data).ok_or(Error::MalformedInteger)
}

fn read_u16<'a>(node: &FdtNode<'a>, property: *const u8) -> Result<u16, Error> {
    let value = read_u64(node, property)?;

    value.try_into().map_err(|_| Error::IntegerOverflow)
}

impl ManifestVm {
    fn new<'a>(node: &FdtNode<'a>, vm_id: spci_vm_id_t) -> Result<Self, Error> {
        let debug_name = read_string(node, "debug_name\0".as_ptr())?;
        let (kernel_filename, mem_size, vcpu_count);

        if vm_id != HF_PRIMARY_VM_ID {
            kernel_filename = read_string(node, "kernel_filename\0".as_ptr())?;
            mem_size = read_u64(node, "mem_size\0".as_ptr())?;
            vcpu_count = read_u16(node, "vcpu_count\0".as_ptr())?;
        } else {
            kernel_filename = unsafe { MemIter::from_raw(ptr::null(), 0) };
            mem_size = 0;
            vcpu_count = 0;
        }

        Ok(Self {
            debug_name,
            kernel_filename,
            mem_size,
            vcpu_count,
        })
    }
}

impl Manifest {
    /// Parse manifest from FDT.
    pub fn init(&mut self, fdt: &MemIter) -> Result<(), Error> {
        let mut vm_name_buf = Default::default();
        let mut found_primary_vm = false;
        let mut hyp_node = FdtNode::new_root(unsafe { &*(fdt.get_next() as *const _) })
            .ok_or(Error::CorruptedFdt)?;
        unsafe {
            self.vms.set_len(0);
        }

        hyp_node
            .find_child("\0".as_ptr())
            .ok_or(Error::NoRootFdtNode)?;
        hyp_node
            .find_child("hypervisor\0".as_ptr())
            .ok_or(Error::NoHypervisorFdtNode)?;

        // Iterate over reserved VM IDs and check no such nodes exist.
        for vm_id in 0..HF_VM_ID_OFFSET {
            let mut vm_node = hyp_node.clone();
            let vm_name = generate_vm_node_name(&mut vm_name_buf, vm_id);

            if vm_node.find_child(vm_name.as_ptr()).is_some() {
                return Err(Error::ReservedVmId);
            }
        }

        // Iterate over VM nodes until we find one that does not exist.
        for i in 0..=MAX_VMS as spci_vm_id_t {
            let vm_id = HF_VM_ID_OFFSET + i;
            let mut vm_node = hyp_node.clone();
            let vm_name = generate_vm_node_name(&mut vm_name_buf, vm_id);

            if vm_node.find_child(vm_name.as_ptr()).is_none() {
                break;
            }

            if i == MAX_VMS as spci_vm_id_t {
                return Err(Error::TooManyVms);
            }

            if vm_id == HF_PRIMARY_VM_ID {
                assert!(found_primary_vm == false); // sanity check
                found_primary_vm = true;
            }

            self.vms.push(ManifestVm::new(&vm_node, vm_id)?);
        }

        if !found_primary_vm {
            Err(Error::NoPrimaryVm)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::fmt::Write as fmtWrite;
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::process::*;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    /// Class for programatically building a Device Tree.
    ///
    /// # Usage
    /// ```
    /// let dtb = ManifestDtBuilder::new()
    ///     .Command1()
    ///     .Command2()
    ///     ...
    ///     .CommandN()
    ///     .Build();
    /// ```
    struct ManifestDtBuilder {
        dts: String,
    }

    impl ManifestDtBuilder {
        fn new() -> Self {
            let mut builder = Self { dts: String::new() };
            builder.dts.push_str("/dts-v1/;\n");
            builder.dts.push_str("\n");

            // Start root node.
            builder.start_child("/");
            builder
        }

        fn build(&mut self) -> Vec<u8> {
            self.end_child();

            let mut child = Command::new("../build/image/dtc.py")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(self.dts.as_bytes())
                .unwrap();

            child.wait_with_output().unwrap().stdout
        }

        fn start_child(&mut self, name: &str) -> &mut Self {
            self.dts.push_str(name);
            self.dts.push_str(" {\n");
            self
        }

        fn end_child(&mut self) -> &mut Self {
            self.dts.push_str("};\n");
            self
        }

        fn debug_name(&mut self, value: &str) -> &mut Self {
            self.string_property("debug_name", value)
        }

        fn kernel_filename(&mut self, value: &str) -> &mut Self {
            self.string_property("kernel_filename", value)
        }

        fn vcpu_count(&mut self, value: u64) -> &mut Self {
            self.integer_property("vcpu_count", value)
        }

        fn mem_size(&mut self, value: u64) -> &mut Self {
            self.integer_property("mem_size", value)
        }

        fn string_property(&mut self, name: &str, value: &str) -> &mut Self {
            write!(self.dts, "{} = \"{}\";\n", name, value).unwrap();
            self
        }

        fn integer_property(&mut self, name: &str, value: u64) -> &mut Self {
            write!(self.dts, "{} = <{}>;\n", name, value).unwrap();
            self
        }
    }

    #[test]
    fn no_hypervisor_node() {
        let dtb = ManifestDtBuilder::new().build();

        let it = unsafe { MemIter::from_raw(dtb.as_ptr(), dtb.len()) };
        let mut m: Manifest = unsafe { MaybeUninit::uninit().assume_init() };
        assert_eq!(m.init(&it).unwrap_err(), Error::NoHypervisorFdtNode);
    }

    #[test]
    fn no_vms() {
        let dtb = ManifestDtBuilder::new()
            .start_child("hypervisor")
            .end_child()
            .build();

        let it = unsafe { MemIter::from_raw(dtb.as_ptr(), dtb.len()) };
        let mut m: Manifest = unsafe { MaybeUninit::uninit().assume_init() };
        assert_eq!(m.init(&it).unwrap_err(), Error::NoPrimaryVm);
    }

    #[test]
    fn reserved_vmid() {
        let dtb = ManifestDtBuilder::new()
            .start_child("hypervisor")
            .start_child("vm1")
            .debug_name("primary_vm")
            .end_child()
            .start_child("vm0")
            .debug_name("reserved_vm")
            .vcpu_count(1)
            .mem_size(0x1000)
            .kernel_filename("kernel")
            .end_child()
            .end_child()
            .build();

        let it = unsafe { MemIter::from_raw(dtb.as_ptr(), dtb.len()) };
        let mut m: Manifest = unsafe { MaybeUninit::uninit().assume_init() };
        assert_eq!(m.init(&it).unwrap_err(), Error::ReservedVmId);
    }

    #[test]
    fn vcpu_count_limit() {
        fn gen_vcpu_count_limit_dtb(vcpu_count: u64) -> Vec<u8> {
            ManifestDtBuilder::new()
                .start_child("hypervisor")
                .start_child("vm1")
                .debug_name("primary_vm")
                .end_child()
                .start_child("vm2")
                .debug_name("secondary_vm")
                .vcpu_count(vcpu_count)
                .mem_size(0x1000)
                .kernel_filename("kernel")
                .end_child()
                .end_child()
                .build()
        }

        let dtb_last_valid = gen_vcpu_count_limit_dtb(u16::max_value() as u64);
        let dtb_first_invalid = gen_vcpu_count_limit_dtb(u16::max_value() as u64 + 1);

        let it = unsafe { MemIter::from_raw(dtb_last_valid.as_ptr(), dtb_last_valid.len()) };
        let mut m: Manifest = unsafe { MaybeUninit::uninit().assume_init() };
        m.init(&it).unwrap();
        assert_eq!(m.vms.len(), 2);
        assert_eq!(m.vms[1].vcpu_count, u16::max_value());

        let it = unsafe { MemIter::from_raw(dtb_first_invalid.as_ptr(), dtb_first_invalid.len()) };
        assert_eq!(m.init(&it).unwrap_err(), Error::IntegerOverflow);
    }

    #[test]
    fn valid() {
        let dtb = ManifestDtBuilder::new()
            .start_child("hypervisor")
            .start_child("vm1")
            .debug_name("primary_vm")
            .end_child()
            .start_child("vm3")
            .debug_name("second_secondary_vm")
            .vcpu_count(43)
            .mem_size(0x12345)
            .kernel_filename("second_kernel")
            .end_child()
            .start_child("vm2")
            .debug_name("first_secondary_vm")
            .vcpu_count(42)
            .mem_size(12345)
            .kernel_filename("first_kernel")
            .end_child()
            .end_child()
            .build();

        let it = unsafe { MemIter::from_raw(dtb.as_ptr(), dtb.len()) };
        let mut m: Manifest = unsafe { MaybeUninit::uninit().assume_init() };
        m.init(&it).unwrap();
        assert_eq!(m.vms.len(), 3);

        let vm = &m.vms[0];
        assert!(unsafe { vm.debug_name.iseq("primary_vm\0".as_ptr()) });

        let vm = &m.vms[1];
        assert!(unsafe { vm.debug_name.iseq("first_secondary_vm\0".as_ptr()) });
        assert_eq!(vm.vcpu_count, 42);
        assert_eq!(vm.mem_size, 12345);
        assert!(unsafe { vm.kernel_filename.iseq("first_kernel\0".as_ptr()) });

        let vm = &m.vms[2];
        assert!(unsafe { vm.debug_name.iseq("second_secondary_vm\0".as_ptr()) });
        assert_eq!(vm.vcpu_count, 43);
        assert_eq!(vm.mem_size, 0x12345);
        assert!(unsafe { vm.kernel_filename.iseq("second_kernel\0".as_ptr()) });
    }
}

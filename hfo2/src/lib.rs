/*
 * Copyright 2019 Jeehoon Kang
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

#![no_std]
#![feature(core_intrinsics)]
#![feature(const_fn_trait_bound)]
#![feature(const_panic)]
#![feature(const_raw_ptr_to_usize_cast)]
#![feature(linkage)]
#![feature(try_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate static_assertions;
extern crate arrayvec;
extern crate reduce;
#[macro_use]
extern crate memoffset;
extern crate scopeguard;

mod cpio;
#[macro_use]
mod utils;
#[macro_use]
mod dlog;
#[macro_use]
mod list;
mod abi;
mod addr;
mod api;
mod arch;
mod boot_flow;
mod boot_params;
mod cpu;
mod fdt;
mod fdt_handler;
mod hypervisor;
mod init;
mod layout;
mod load;
mod manifest;
mod memiter;
mod mm;
mod mpool;
mod page;
mod panic;
mod slist;
mod spci;
mod spci_architected_message;
mod spinlock;
mod std;
mod types;
mod vm;

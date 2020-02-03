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

use core::ptr;

use crate::types::*;

/// Check whether the value `v` is aligned to the boundary `a`,
/// with `a` power of 2.
pub fn is_aligned(v: usize, a: usize) -> bool {
    (v & (a - 1)) == 0
}

/// As per the C11 specification, mem*_s() operations fill the destination buffer if runtime
/// constraint validation fails, assuming that `dest` and `destsz` are both valid.
/// Note(HfO2): The function name is automatically included by `panic!` macro.
macro_rules! check_or_fill {
    ($cond:expr, $dest:expr, $destsz:expr, $ch:expr) => {{
        if !$cond {
            if (!$dest.is_null() && $destsz <= RSIZE_MAX) {
                memset_s($dest, $destsz, $ch, $destsz);
            }
            panic!("failed: {}", stringify!($cond));
        }
    }};

    ($cond:expr, $dest:expr, $destsz:expr) => {{
        check_or_fill!($cond, $dest, $destsz, 0)
    }};
}

#[no_mangle]
pub unsafe extern "C" fn memset_s(dest: *const c_void, destsz: size_t, ch: c_int, count: size_t) {
    check_or_fill!(!dest.is_null(), dest, destsz, ch);

    // Check count <= destsz <= RSIZE_MAX.
    check_or_fill!(destsz <= RSIZE_MAX, dest, destsz, ch);
    check_or_fill!(count <= destsz, dest, destsz, ch);

    ptr::write_bytes(dest as *mut u8, ch as u8, count);
}

#[no_mangle]
pub unsafe extern "C" fn memcpy_s(
    dest: *mut c_void,
    destsz: size_t,
    src: *const c_void,
    count: size_t,
) {
    let d = dest as usize;
    let s = src as usize;

    check_or_fill!(!dest.is_null(), dest, destsz);
    check_or_fill!(!src.is_null(), dest, destsz);

    // Check count <= destsz <= RSIZE_MAX.
    check_or_fill!(destsz <= RSIZE_MAX, dest, destsz);
    check_or_fill!(count <= destsz, dest, destsz);

    // Buffer overlap test.
    // case a) `d < s` impiles `s >= d+count`
    // case b) `d > s` impiles `d >= s+count`
    check_or_fill!(d != s, dest, destsz);
    check_or_fill!(d < s || d >= (s + count), dest, destsz);
    check_or_fill!(d > s || s >= (d + count), dest, destsz);

    ptr::copy_nonoverlapping(src as *const u8, dest as *mut u8, count);
}

#[no_mangle]
pub unsafe extern "C" fn memmove_s(
    dest: *mut c_void,
    destsz: size_t,
    src: *const c_void,
    count: size_t,
) {
    check_or_fill!(!dest.is_null(), dest, destsz);
    check_or_fill!(!src.is_null(), dest, destsz);

    // Check count <= destsz <= RSIZE_MAX.
    check_or_fill!(destsz <= RSIZE_MAX, dest, destsz);
    check_or_fill!(count <= destsz, dest, destsz);

    ptr::copy(src as *const u8, dest as *mut u8, count);
}

/// Returns the length of the null-terminated byte string `str`, examining at most `strsz` bytes.
///
/// If `str` is a NULL pointer, it returns zero.
/// If a NULL character is not found, it returns `strsz`.
#[no_mangle]
pub unsafe extern "C" fn strnlen_s(str: *const c_char, mut strsz: size_t) -> size_t {
    if str.is_null() {
        return 0;
    }

    for i in 0..strsz {
        if *str.add(i) == b'\0' {
            return i;
        }
    }

    // NULL character not found.
    strsz
}

pub(crate) unsafe fn memcmp_rs(a: *const c_void, b: *const c_void, mut n: size_t) -> c_int {
    let mut a = a as *const u8;
    let mut b = b as *const u8;

    while n > 0 {
        let cmp = *a - *b;
        if cmp != 0 {
            return c_int::from(cmp);
        }

        a = a.add(1);
        b = b.add(1);
        n -= 1;
    }

    0
}

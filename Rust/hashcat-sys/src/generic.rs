/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    mem, slice,
};

pub use crate::bindings::{bridge_context_t, generic_io_t, generic_io_tmp_t, salt_t};

/// What one bridge thread is handed for the whole run. The 2 generic bridges keep the same shape,
/// because 1 C bridge loads either of them through 1 fixed new_context () signature.
#[repr(C)]
pub struct ThreadContext {
    pub module_name: String,

    pub salts: Vec<salt_t>,
    pub esalts: Vec<generic_io_t>,
    pub st_salts: Vec<salt_t>,
    pub st_esalts: Vec<generic_io_t>,

    pub bridge_parameter1: String,
    pub bridge_parameter2: String,
    pub bridge_parameter3: String,
    pub bridge_parameter4: String,

    // Under attack mode 9 salt_id is the salt the batch starts at and each candidate adds its own
    // position in it. Every other attack has one salt for the whole batch.
    pub salt_per_pw: bool,
}

impl ThreadContext {
    pub fn get_raw_esalt(&self, salt_id: usize, is_selftest: bool) -> &generic_io_t {
        // There is one esalt per hash but one salt per distinct salt, so the two only line up when
        // every salt holds one hash. A salt names the first of its hashes with digests_offset.
        let (salts, esalts) = if is_selftest {
            (&self.st_salts, &self.st_esalts)
        } else {
            (&self.salts, &self.esalts)
        };

        &esalts[salts[salt_id].digests_offset as usize]
    }
}

/// Copy an array of `length` values of type T out of C memory.
///
/// # Safety
///
/// `data` must point at `length` initialised, aligned values of T that stay valid for the call. A
/// pointer that merely survives a null check can still be dangling or misaligned, and a `length`
/// that does not match the allocation is undefined behaviour whatever the pointer is, so the
/// obligation stays with the caller. A `length` of 0 reads nothing, so `data` may then be null.
pub unsafe fn vec_from_raw_parts<T: Clone>(data: *const T, length: c_int) -> Vec<T> {
    if length == 0 {
        return Vec::new();
    }

    Vec::from(unsafe { slice::from_raw_parts(data, length as usize) })
}

/// Copy a C string out of C memory, or an empty String when it is null.
///
/// # Safety
///
/// `ptr` must be null or point at a NUL terminated string that stays valid for the call.
pub unsafe fn string_from_ptr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().unwrap_or_default().to_string() }
    }
}

/// Build a `ThreadContext` and hand the core a void* to it.
#[unsafe(no_mangle)]
pub extern "C" fn new_context(
    module_name: *const c_char,

    salts_cnt: c_int,
    salts_size: c_int,
    salts_buf: *const c_char,

    esalts_cnt: c_int,
    esalts_size: c_int,
    esalts_buf: *const c_char,

    st_salts_cnt: c_int,
    st_salts_size: c_int,
    st_salts_buf: *const c_char,

    st_esalts_cnt: c_int,
    st_esalts_size: c_int,
    st_esalts_buf: *const c_char,

    bridge_parameter1: *const c_char,
    bridge_parameter2: *const c_char,
    bridge_parameter3: *const c_char,
    bridge_parameter4: *const c_char,
    salt_per_pw: bool,
) -> *mut c_void {
    assert!(!module_name.is_null());
    assert!(!salts_buf.is_null());
    assert!(!esalts_buf.is_null());
    // A run without a self-test hash has no self-test salt, and the core says so with a count of 0.
    assert!((st_salts_cnt == 0) || (st_salts_buf.is_null() == false));
    assert!((st_esalts_cnt == 0) || (st_esalts_buf.is_null() == false));
    assert_eq!(salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(st_salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(esalts_size as usize, mem::size_of::<generic_io_t>());
    assert_eq!(st_esalts_size as usize, mem::size_of::<generic_io_t>());
    let module_name = unsafe { string_from_ptr(module_name) };
    let salts = unsafe { vec_from_raw_parts(salts_buf as *const salt_t, salts_cnt) };
    let esalts = unsafe { vec_from_raw_parts(esalts_buf as *const generic_io_t, esalts_cnt) };
    let st_salts = unsafe { vec_from_raw_parts(st_salts_buf as *const salt_t, st_salts_cnt) };
    let st_esalts =
        unsafe { vec_from_raw_parts(st_esalts_buf as *const generic_io_t, st_esalts_cnt) };

    let bridge_parameter1 = unsafe { string_from_ptr(bridge_parameter1) };
    let bridge_parameter2 = unsafe { string_from_ptr(bridge_parameter2) };
    let bridge_parameter3 = unsafe { string_from_ptr(bridge_parameter3) };
    let bridge_parameter4 = unsafe { string_from_ptr(bridge_parameter4) };

    Box::into_raw(Box::new(ThreadContext {
        module_name,
        salts,
        esalts,
        st_salts,
        st_esalts,
        bridge_parameter1,
        bridge_parameter2,
        bridge_parameter3,
        bridge_parameter4,
        salt_per_pw,
    })) as *mut c_void
}

/// Free a `ThreadContext` the core is done with.
#[unsafe(no_mangle)]
pub extern "C" fn drop_context(ctx: *mut c_void) {
    assert!(!ctx.is_null());
    unsafe {
        drop(Box::from_raw(ctx as *mut ThreadContext));
    }
}

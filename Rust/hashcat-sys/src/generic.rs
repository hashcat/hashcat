use anyhow::{Result, anyhow};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    mem, slice,
};

use crate::{ThreadContext, generic_io_t, salt_t};

/// convert an array of data of a given type T to a Vec<T>
pub fn vec_from_raw<T: Clone>(data: *const T, length: c_int) -> Result<Vec<T>> {
    if data.is_null() {
        Err(anyhow!("null pointer encountered in conversion to Vec<T>"))
    } else {
        Ok(Vec::from(unsafe {
            slice::from_raw_parts(data, length as usize)
        }))
    }
}

/// convert a C char* to a Rust String
pub fn string_from_ptr(ptr: *const c_char) -> Result<String> {
    if ptr.is_null() {
        Err(anyhow!("null pointer encountered in conversion to String"))
    } else {
        Ok(unsafe { CStr::from_ptr(ptr).to_str().unwrap_or_default().to_string() })
    }
}

/// creates an instance of `ThreadContext` and returns a void* to it
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
) -> *mut c_void {
    assert!(!module_name.is_null());
    assert!(!salts_buf.is_null());
    assert!(!esalts_buf.is_null());
    assert!(!st_salts_buf.is_null());
    assert!(!st_esalts_buf.is_null());
    assert_eq!(salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(st_salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(esalts_size as usize, mem::size_of::<generic_io_t>());
    assert_eq!(st_esalts_size as usize, mem::size_of::<generic_io_t>());
    let module_name = string_from_ptr(module_name).unwrap_or_default();
    let salts = vec_from_raw(salts_buf as *const salt_t, salts_cnt).unwrap_or_default();
    let esalts = vec_from_raw(esalts_buf as *const generic_io_t, esalts_cnt).unwrap_or_default();
    let st_salts = vec_from_raw(st_salts_buf as *const salt_t, st_salts_cnt).unwrap_or_default();
    let st_esalts =
        vec_from_raw(st_esalts_buf as *const generic_io_t, st_esalts_cnt).unwrap_or_default();

    let bridge_parameter1 = string_from_ptr(bridge_parameter1).unwrap_or_default();
    let bridge_parameter2 = string_from_ptr(bridge_parameter2).unwrap_or_default();
    let bridge_parameter3 = string_from_ptr(bridge_parameter3).unwrap_or_default();
    let bridge_parameter4 = string_from_ptr(bridge_parameter4).unwrap_or_default();

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
    })) as *mut c_void
}

use anyhow::{anyhow, Result};
use std::{
    ffi::{c_char, c_int, CStr},
    slice,
};

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

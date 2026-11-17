/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    mem, panic, ptr, slice,
    sync::atomic::{AtomicBool, Ordering},
};

pub use crate::bindings::{bridge_context_t, generic_io_t, generic_io_tmp_t, salt_t};

/// What one bridge thread is handed for the whole run. The 2 generic bridges keep the same shape,
/// because 1 C bridge loads either of them through 1 fixed new_context () signature.
#[repr(C)]
pub struct ThreadContext {
    pub module_name: String,

    pub salts: Vec<salt_t>,
    pub esalts: Vec<Vec<u8>>,
    pub st_salts: Vec<salt_t>,
    pub st_esalts: Vec<Vec<u8>>,

    pub bridge_parameter1: String,
    pub bridge_parameter2: String,
    pub bridge_parameter3: String,
    pub bridge_parameter4: String,

    // Under attack mode 9 salt_id is the salt the batch starts at and each candidate adds its own
    // position in it. Every other attack has one salt for the whole batch.
    pub salt_per_pw: bool,
}

impl ThreadContext {
    pub fn get_raw_esalt(&self, salt_id: usize, is_selftest: bool) -> &[u8] {
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

fn unpack_esalts(data: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut pos = 0;
    let mut salts = Vec::with_capacity(count);

    for _ in 0..count {
        let header = data
            .get(pos..pos + 8)
            .expect("truncated generic record header");
        let hash_len = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
        let salt_len = u32::from_ne_bytes(header[4..].try_into().unwrap()) as usize;
        pos += 8;

        let end = pos
            .checked_add(hash_len)
            .and_then(|n| n.checked_add(salt_len))
            .expect("generic record length overflow");
        let record = data.get(pos..end).expect("truncated generic record data");
        salts.push(record[hash_len..].to_vec());
        pos = end;
    }

    assert_eq!(pos, data.len(), "extra generic record data");

    salts
}

#[cfg(test)]
mod packed_tests {
    use super::unpack_esalts;

    #[test]
    fn large_salt_and_multiple_records() {
        let salt = vec![b'a'; 131_072];
        let mut data = Vec::new();
        data.extend_from_slice(&4_u32.to_ne_bytes());
        data.extend_from_slice(&(salt.len() as u32).to_ne_bytes());
        data.extend_from_slice(b"hash");
        data.extend_from_slice(&salt);
        data.extend_from_slice(&0_u32.to_ne_bytes());
        data.extend_from_slice(&1_u32.to_ne_bytes());
        data.push(b'z');

        assert_eq!(unpack_esalts(&data, 2), vec![salt, vec![b'z']]);
    }

    #[test]
    #[should_panic(expected = "truncated generic record data")]
    fn truncated_record() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_u32.to_ne_bytes());
        data.extend_from_slice(&2_u32.to_ne_bytes());
        data.push(b'a');
        unpack_esalts(&data, 1);
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

static POISONED: AtomicBool = AtomicBool::new(false);

/// Run `f` and turn a panic into `false`. The default hook has already printed the panic on stderr,
/// and a false return reaches hashcat as a bridge error, where a panic leaving an extern "C" fn
/// aborts hashcat before it can say anything. After one panic every later call returns false.
pub fn no_panic<F: FnOnce() -> bool>(f: F) -> bool {
    if POISONED.load(Ordering::Relaxed) {
        return false;
    }
    match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(ok) => ok,
        Err(_) => {
            POISONED.store(true, Ordering::Relaxed);
            false
        }
    }
}

/// The same for an entry point that returns nothing, such as thread_init. A panic there makes the
/// next call that can return false do so.
pub fn no_panic_void<F: FnOnce()>(f: F) {
    no_panic(|| {
        f();
        true
    });
}

/// Build a `ThreadContext` and hand the core a void* to it, or NULL after a panic, which the core
/// reports as a failed thread init.
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
    let mut out: *mut c_void = ptr::null_mut();
    no_panic(|| {
        out = new_context_inner(
            module_name,
            salts_cnt,
            salts_size,
            salts_buf,
            esalts_cnt,
            esalts_size,
            esalts_buf,
            st_salts_cnt,
            st_salts_size,
            st_salts_buf,
            st_esalts_cnt,
            st_esalts_size,
            st_esalts_buf,
            bridge_parameter1,
            bridge_parameter2,
            bridge_parameter3,
            bridge_parameter4,
            salt_per_pw,
        );
        true
    });
    out
}

#[allow(clippy::too_many_arguments)]
fn new_context_inner(
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
    assert!((esalts_cnt == 0) || (esalts_buf.is_null() == false));
    // A run without a self-test hash has no self-test salt, and the core says so with a count of 0.
    assert!((st_salts_cnt == 0) || (st_salts_buf.is_null() == false));
    assert!((st_esalts_cnt == 0) || (st_esalts_buf.is_null() == false));
    assert_eq!(salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(st_salts_size as usize, mem::size_of::<salt_t>());
    let module_name = unsafe { string_from_ptr(module_name) };
    let salts = unsafe { vec_from_raw_parts(salts_buf as *const salt_t, salts_cnt) };
    let esalts_data = if esalts_size == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(esalts_buf as *const u8, esalts_size as usize) }
    };
    let esalts = unpack_esalts(esalts_data, esalts_cnt as usize);
    let st_salts = unsafe { vec_from_raw_parts(st_salts_buf as *const salt_t, st_salts_cnt) };
    let st_esalts_data = if st_esalts_size == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(st_esalts_buf as *const u8, st_esalts_size as usize) }
    };
    let st_esalts = unpack_esalts(st_esalts_data, st_esalts_cnt as usize);

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
    no_panic_void(|| {
        assert!(!ctx.is_null());
        unsafe {
            drop(Box::from_raw(ctx as *mut ThreadContext));
        }
    });
}

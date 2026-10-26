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

#[unsafe(no_mangle)]
pub extern "C" fn generic_io_size() -> u64 {
    mem::size_of::<generic_io_t>() as u64
}

#[derive(Debug)]
pub struct GenericIo {
    pub hash_buf: Vec<u8>,
    pub hash_len: u32,
    pub salt_buf: Vec<u8>,
    pub salt_len: u32,
}

fn packed_esalts(data: &[u8], count: usize) -> Result<Vec<GenericIo>, &'static str> {
    if count > data.len() / 8 {
        return Err("truncated generic bridge record headers");
    }

    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| "cannot allocate generic bridge records")?;
    let mut pos = 0usize;

    for _ in 0..count {
        let header = data
            .get(pos..pos + 8)
            .ok_or("truncated generic bridge record header")?;
        let hash_len = u32::from_ne_bytes(header[..4].try_into().unwrap());
        let salt_len = u32::from_ne_bytes(header[4..].try_into().unwrap());
        pos += 8;

        let hash_end = pos
            .checked_add(hash_len as usize)
            .ok_or("generic bridge record overflow")?;
        let end = hash_end
            .checked_add(salt_len as usize)
            .ok_or("generic bridge record overflow")?;
        let hash = data
            .get(pos..hash_end)
            .ok_or("truncated generic bridge hash")?;
        let salt = data
            .get(hash_end..end)
            .ok_or("truncated generic bridge salt")?;

        let mut hash_buf = Vec::new();
        hash_buf
            .try_reserve_exact(hash.len())
            .map_err(|_| "cannot allocate generic bridge hash")?;
        hash_buf.extend_from_slice(hash);
        let mut salt_buf = Vec::new();
        salt_buf
            .try_reserve_exact(salt.len())
            .map_err(|_| "cannot allocate generic bridge salt")?;
        salt_buf.extend_from_slice(salt);

        records.push(GenericIo {
            hash_buf,
            hash_len,
            salt_buf,
            salt_len,
        });
        pos = end;
    }

    if pos != data.len() {
        return Err("extra generic bridge record data");
    }

    Ok(records)
}

/// What one bridge thread is handed for the whole run. The 2 generic bridges keep the same shape,
/// because 1 C bridge loads either of them through 1 fixed new_context () signature.
#[repr(C)]
pub struct ThreadContext {
    pub module_name: String,

    pub salts: Vec<salt_t>,
    pub esalts: Vec<GenericIo>,
    pub st_salts: Vec<salt_t>,
    pub st_esalts: Vec<GenericIo>,

    pub bridge_parameter1: String,
    pub bridge_parameter2: String,
    pub bridge_parameter3: String,
    pub bridge_parameter4: String,

    // Under attack mode 9 salt_id is the salt the batch starts at and each candidate adds its own
    // position in it. Every other attack has one salt for the whole batch.
    pub salt_per_pw: bool,
}

impl ThreadContext {
    pub fn get_raw_esalt(&self, salt_id: usize, is_selftest: bool) -> &GenericIo {
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
    esalts_len: c_int,
    esalts_buf: *const c_char,

    st_salts_cnt: c_int,
    st_salts_size: c_int,
    st_salts_buf: *const c_char,

    st_esalts_cnt: c_int,
    st_esalts_len: c_int,
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
            esalts_len,
            esalts_buf,
            st_salts_cnt,
            st_salts_size,
            st_salts_buf,
            st_esalts_cnt,
            st_esalts_len,
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
    esalts_len: c_int,
    esalts_buf: *const c_char,

    st_salts_cnt: c_int,
    st_salts_size: c_int,
    st_salts_buf: *const c_char,

    st_esalts_cnt: c_int,
    st_esalts_len: c_int,
    st_esalts_buf: *const c_char,

    bridge_parameter1: *const c_char,
    bridge_parameter2: *const c_char,
    bridge_parameter3: *const c_char,
    bridge_parameter4: *const c_char,
    salt_per_pw: bool,
) -> *mut c_void {
    assert!(!module_name.is_null());
    assert!(!salts_buf.is_null());
    // A run without a self-test hash has no self-test salt, and the core says so with a count of 0.
    assert!((st_salts_cnt == 0) || (st_salts_buf.is_null() == false));
    assert!((st_esalts_cnt == 0) || (st_esalts_buf.is_null() == false));
    assert_eq!(salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(st_salts_size as usize, mem::size_of::<salt_t>());
    if esalts_cnt < 0 || esalts_len < 0 || st_esalts_cnt < 0 || st_esalts_len < 0 {
        return std::ptr::null_mut();
    }
    if (esalts_len > 0 && esalts_buf.is_null()) || (st_esalts_len > 0 && st_esalts_buf.is_null()) {
        return std::ptr::null_mut();
    }

    let data = if esalts_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(esalts_buf.cast::<u8>(), esalts_len as usize) }
    };
    let st_data = if st_esalts_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(st_esalts_buf.cast::<u8>(), st_esalts_len as usize) }
    };
    let (esalts, st_esalts) = match (
        packed_esalts(data, esalts_cnt as usize),
        packed_esalts(st_data, st_esalts_cnt as usize),
    ) {
        (Ok(esalts), Ok(st_esalts)) => (esalts, st_esalts),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("Invalid generic bridge records: {error}");
            return std::ptr::null_mut();
        }
    };

    let module_name = unsafe { string_from_ptr(module_name) };
    let salts = unsafe { vec_from_raw_parts(salts_buf as *const salt_t, salts_cnt) };
    let st_salts = unsafe { vec_from_raw_parts(st_salts_buf as *const salt_t, st_salts_cnt) };

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

#[cfg(test)]
mod packed_tests {
    use super::packed_esalts;

    fn record(hash: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(hash.len() as u32).to_ne_bytes());
        data.extend_from_slice(&(salt.len() as u32).to_ne_bytes());
        data.extend_from_slice(hash);
        data.extend_from_slice(salt);
        data
    }

    #[test]
    fn variable_records() {
        let salt = vec![b'x'; 131072];
        let mut data = record(b"", b"");
        data.extend_from_slice(&record(b"hash", b"short"));
        data.extend_from_slice(&record(b"other", &salt));
        assert_eq!(data.len(), 24 + 4 + 5 + 5 + salt.len());

        let records = packed_esalts(&data, 3).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records[0].hash_buf.is_empty());
        assert!(records[0].salt_buf.is_empty());
        assert_eq!(records[1].hash_buf, b"hash");
        assert_eq!(records[1].salt_buf, b"short");
        assert_eq!(records[2].salt_buf, salt);
        assert!(packed_esalts(&[], 0).unwrap().is_empty());
    }

    #[test]
    fn malformed_records() {
        let data = record(b"hash", b"short");
        for end in 0..data.len() {
            assert!(packed_esalts(&data[..end], 1).is_err());
        }
        assert!(packed_esalts(&data, 0).is_err());
        assert!(packed_esalts(&data, 2).is_err());
        let mut extra = data.clone();
        extra.push(b'x');
        assert!(packed_esalts(&extra, 1).is_err());

        let mut overflow = Vec::new();
        overflow.extend_from_slice(&u32::MAX.to_ne_bytes());
        overflow.extend_from_slice(&u32::MAX.to_ne_bytes());
        assert!(packed_esalts(&overflow, 1).is_err());
    }
}

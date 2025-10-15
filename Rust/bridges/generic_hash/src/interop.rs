/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::{
    ffi::{c_char, c_int, c_void},
    mem,
    path::Path,
    ptr, slice,
    sync::OnceLock,
};

use hashcat_sys::{
    bridge_context_t,
    common::{string_from_ptr, vec_from_raw},
    generic_io_t, generic_io_tmp_t, salt_t,
};

use crate::generic_hash;

static INFO: OnceLock<&'static str> = OnceLock::new();

#[repr(C)]
pub(crate) struct ThreadContext {
    pub module_name: String,

    pub salts: Vec<salt_t>,
    pub esalts: Vec<generic_io_t>,
    pub st_salts: Vec<salt_t>,
    pub st_esalts: Vec<generic_io_t>,

    pub bridge_parameter1: String,
    pub bridge_parameter2: String,
    pub bridge_parameter3: String,
    pub bridge_parameter4: String,
}

impl ThreadContext {
    fn get_raw_esalt(&self, salt_id: usize, is_selftest: bool) -> &generic_io_t {
        if is_selftest {
            &self.st_esalts[salt_id]
        } else {
            &self.esalts[salt_id]
        }
    }
}

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

#[unsafe(no_mangle)]
pub extern "C" fn drop_context(ctx: *mut c_void) {
    assert!(!ctx.is_null());
    unsafe {
        drop(Box::from_raw(ctx as *mut ThreadContext));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn get_info(buf: *mut c_char, buf_size: c_int) -> c_int {
    assert!(buf_size > 0);
    let info = INFO.get().unwrap_or(&"");
    let n = info.len().min(buf_size as usize);
    unsafe {
        ptr::copy_nonoverlapping(info.as_ptr(), buf as *mut u8, n);
    }
    n as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn global_init(ctx: *mut bridge_context_t) -> bool {
    assert!(!ctx.is_null());
    let ctx = unsafe { &mut *ctx };
    assert!(!ctx.dynlib_filename.is_null());

    let dynlib_name = string_from_ptr(ctx.dynlib_filename).unwrap_or_default();
    let dynlib_name = Path::new(&dynlib_name)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    let info = format!("Rust [{}]", dynlib_name);
    INFO.set(info.leak()).expect("global_init called twice");
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn global_term(_ctx: *mut bridge_context_t) {}

#[unsafe(no_mangle)]
pub extern "C" fn thread_init(ctx: *mut c_void) {
    assert!(!ctx.is_null());
    let ctx = unsafe { &mut *ctx.cast::<ThreadContext>() };
    generic_hash::thread_init(ctx);
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_term(ctx: *mut c_void) {
    assert!(!ctx.is_null());
    let ctx = unsafe { &mut *ctx.cast::<ThreadContext>() };
    generic_hash::thread_term(ctx);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_loop(
    ctx: *const c_void,
    io: *mut generic_io_tmp_t,
    pws_cnt: u64,
    salt_id: c_int,
    is_selftest: bool,
) -> bool {
    assert!(!ctx.is_null());
    assert!(!io.is_null());
    let io = unsafe { slice::from_raw_parts_mut(io, pws_cnt as usize) };

    let ctx = unsafe { &*ctx.cast::<ThreadContext>() };

    let results = process_batch(ctx, io, salt_id as usize, is_selftest);

    assert_eq!(results.len(), pws_cnt as usize);

    for (dst, src) in io.iter_mut().zip(results) {
        dst.out_cnt = src.len() as u32;
        assert!(
            src.len() <= dst.out_buf.len(),
            "calc_hash should return no more than {} hashes",
            dst.out_buf.len()
        );
        for (s, (buf, len)) in src
            .iter()
            .zip(dst.out_buf.iter_mut().zip(dst.out_len.iter_mut()))
        {
            assert!(s.len() <= mem::size_of_val(buf), "digest size too big");
            unsafe {
                ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr() as *mut u8, s.len());
            }
            *len = s.len() as u32;
        }
    }
    true
}

fn process_batch(
    ctx: &ThreadContext,
    io: &[generic_io_tmp_t],
    salt_id: usize,
    is_selftest: bool,
) -> Vec<Vec<String>> {
    let esalt = ctx.get_raw_esalt(salt_id, is_selftest);
    let salt = unsafe {
        slice::from_raw_parts(
            esalt.salt_buf.as_ptr() as *const u8,
            esalt.salt_len as usize,
        )
    };
    io.iter()
        .map(|x| {
            let pw =
                unsafe { slice::from_raw_parts(x.pw_buf.as_ptr() as *const u8, x.pw_len as usize) };
            generic_hash::calc_hash(pw, salt)
        })
        .collect()
}

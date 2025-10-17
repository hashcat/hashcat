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

use hashcat_sys::{ThreadContext, bridge_context_t, common::string_from_ptr, generic_io_tmp_t};

use crate::generic_hash;

static INFO: OnceLock<&'static str> = OnceLock::new();

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

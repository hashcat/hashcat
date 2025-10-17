/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::{
    cell::OnceCell,
    ffi::{c_char, c_int, c_void},
    mem,
    path::Path,
    process, ptr, slice,
    sync::{Once, OnceLock},
};

use hashcat_sys::{ThreadContext, bridge_context_t, common::string_from_ptr, generic_io_tmp_t};

use crate::{Expr, eval::EvalContext, parse};

thread_local! {
    static AST: OnceCell<Expr> = OnceCell::new();
}

static LOG_ERROR_ONCE: Once = Once::new();

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
    let algorithm = string_from_ptr(ctx.bridge_parameter2).unwrap_or_default();
    match parse::parse(&algorithm) {
        Ok(_) => {
            let info = format!("Rust [{}] [{}]", dynlib_name, algorithm);
            INFO.set(info.leak()).expect("global_init called twice");
            true
        }
        Err(err) => {
            eprintln!("ERROR: failed to parse --bridge-parameter2 value: {}", err);
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn global_term(_ctx: *mut bridge_context_t) {}

#[unsafe(no_mangle)]
pub extern "C" fn thread_init(ctx: *mut c_void) {
    assert!(!ctx.is_null());
    let ctx = unsafe { &mut *ctx.cast::<ThreadContext>() };
    let ast = parse::parse(&ctx.bridge_parameter2).expect("invalid algorithm description");
    AST.with(|c| c.set(ast).unwrap_or_default());
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_term(_ctx: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_loop(
    ctx: *const c_void,
    io: *mut generic_io_tmp_t,
    pws_cnt: u64,
    salt_id: c_int,
    _is_self_test: bool,
) -> bool {
    assert!(!ctx.is_null());
    assert!(!io.is_null());
    let io = unsafe { slice::from_raw_parts_mut(io, pws_cnt as usize) };

    let ctx = unsafe { &*ctx.cast::<ThreadContext>() };

    process_batch(ctx, io, salt_id as usize);

    true
}

fn process_batch(ctx: &ThreadContext, io: &mut [generic_io_tmp_t], salt_id: usize) {
    let esalt = ctx.get_raw_esalt(salt_id, false);
    let salt = unsafe {
        slice::from_raw_parts(
            esalt.salt_buf.as_ptr() as *const u8,
            esalt.salt_len as usize,
        )
    };

    let mut eval_ctx = EvalContext::new();
    eval_ctx.set_var("s", salt);
    if salt.contains(&b'*') {
        for (i, s) in salt.split(|&b| b == b'*').enumerate() {
            eval_ctx.set_var(format!("s{}", i + 1), s);
        }
    }

    for in_out in io {
        let pw = unsafe {
            slice::from_raw_parts(in_out.pw_buf.as_ptr() as *const u8, in_out.pw_len as usize)
        };
        eval_ctx.set_var("p", pw);

        let hash = AST
            .with(|c| {
                let ast = c.get().expect("no algorithm");
                eval_ctx.eval(ast)
            })
            .unwrap_or_else(|e| {
                LOG_ERROR_ONCE.call_once(|| eprintln!("ERROR: {}", e));
                process::exit(-1);
            });
        assert!(hash.len() <= mem::size_of_val(&in_out.out_buf[0]));

        in_out.out_cnt = 1;
        unsafe {
            ptr::copy_nonoverlapping(
                hash.as_ptr(),
                in_out.out_buf[0].as_mut_ptr() as *mut u8,
                hash.len(),
            );
        }
        in_out.out_len[0] = hash.len() as u32;
    }
}

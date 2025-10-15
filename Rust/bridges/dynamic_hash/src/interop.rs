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

use hashcat_sys::{
    bridge_context_t,
    common::{string_from_ptr, vec_from_raw},
    generic_io_t, generic_io_tmp_t, salt_t,
};

use crate::{eval::EvalContext, parse, Expr};

thread_local! {
    static AST: OnceCell<Expr> = OnceCell::new();
}

static LOG_ERROR_ONCE: Once = Once::new();

static INFO: OnceLock<&'static str> = OnceLock::new();

#[repr(C)]
pub(crate) struct ThreadContext {
    pub module_name: String,

    pub salts: Vec<salt_t>,
    pub esalts: Vec<generic_io_t>,

    pub bridge_parameter1: String,
    pub bridge_parameter2: String,
    pub bridge_parameter3: String,
    pub bridge_parameter4: String,
}

impl ThreadContext {
    fn get_raw_esalt(&self, salt_id: usize) -> &generic_io_t {
        &self.esalts[salt_id]
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

    _st_salts_cnt: c_int,
    _st_salts_size: c_int,
    _st_salts_buf: *const c_char,

    _st_esalts_cnt: c_int,
    _st_esalts_size: c_int,
    _st_esalts_buf: *const c_char,

    bridge_parameter1: *const c_char,
    bridge_parameter2: *const c_char,
    bridge_parameter3: *const c_char,
    bridge_parameter4: *const c_char,
) -> *mut c_void {
    assert!(!module_name.is_null());
    assert!(!salts_buf.is_null());
    assert!(!esalts_buf.is_null());
    assert_eq!(salts_size as usize, mem::size_of::<salt_t>());
    assert_eq!(esalts_size as usize, mem::size_of::<generic_io_t>());
    let module_name = string_from_ptr(module_name).unwrap_or_default();
    let salts = vec_from_raw(salts_buf as *const salt_t, salts_cnt).unwrap_or_default();
    let esalts = vec_from_raw(esalts_buf as *const generic_io_t, esalts_cnt).unwrap_or_default();

    let bridge_parameter1 = string_from_ptr(bridge_parameter1).unwrap_or_default();
    let bridge_parameter2 = string_from_ptr(bridge_parameter2).unwrap_or_default();
    let bridge_parameter3 = string_from_ptr(bridge_parameter3).unwrap_or_default();
    let bridge_parameter4 = string_from_ptr(bridge_parameter4).unwrap_or_default();

    Box::into_raw(Box::new(ThreadContext {
        module_name,
        salts,
        esalts,
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
    let esalt = ctx.get_raw_esalt(salt_id);
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

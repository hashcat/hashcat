// The Rust twin of src/feeds/feed_dummy.c. It generates the same words from the same seed, so the
// two can be compared word for word to check a port.
//
// It generates from a deterministic pseudo random sequence, which makes it the simplest kind of feed
// that cannot seek: word number N only exists once the generator has produced the N words before it.
// seek() therefore reseeds and replays, which is what any probabilistic generator has to do.
//
// Because the sequence is a pure function of the seed, every device produces the same word for the
// same offset, so hashcat can hand different ranges to different devices and a --restore lands on
// the word it left off at. A generator seeded from the clock or from a thread id cannot do either.

use std::os::raw::{c_char, c_int, c_void};

#[unsafe(no_mangle)]
pub static GENERIC_PLUGIN_OPTIONS: u32 = 0;

// The interface this feed implements. A C feed takes this from FEEDS_INTERFACE_VERSION_CURRENT on the
// compile line, and cargo's equivalent is the environment, which src/feeds/rust_support.mk sets. It
// must not be written out here: a number in the source would survive an interface change and go on
// claiming a compatibility the source no longer has.
//
// Built by hand, with no version in the environment, this stays 0 and hashcat refuses the feed with
// "Plugin version is outdated". That is the intended outcome. Silently guessing a plausible number
// would be the one failure worth avoiding.

const fn parse_version(s: &str) -> u32 {
  let bytes = s.as_bytes();

  let mut out = 0;
  let mut i = 0;

  while i < bytes.len() {
    out = out * 10 + (bytes[i] - b'0') as u32;
    i += 1;
  }

  out
}

#[unsafe(no_mangle)]
pub static GENERIC_PLUGIN_VERSION: u32 = parse_version(match option_env!("FEEDS_INTERFACE_VERSION_CURRENT") {
  Some(v) => v,
  None    => "0",
});

const GENERIC_KEYSPACE_UNKNOWN: u64 = 0xffff_ffff_ffff_ffff;

const GENERIC_RC_EOF: c_int = -1;

// Any fixed value works. What matters is that it never changes between runs, because it is what
// makes --restore and multi device splitting land on the same words.

const DUMMY_SEED: u64 = 0x2545_f491_4f6c_dd1d;

const DUMMY_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[repr(C)]
pub struct generic_global_ctx_t {
    pub quiet: bool,

    pub workc: i32,
    pub workv: *mut *mut c_char,

    pub profile_dir: *mut c_char,
    pub cache_dir: *mut c_char,

    pub error: bool,
    pub error_msg: [c_char; 256],

    pub gbldata: *mut c_void,
}

#[repr(C)]
pub struct generic_thread_ctx_t {
    pub error: bool,
    pub error_msg: [c_char; 256],

    pub thrdata: *mut c_void,
}

struct DummyThread {
    state: u64,
    pos: u64,
}

// xorshift64*. Small, has no state to allocate and repeats after 2^64 - 1 words, which is more than
// a feed will ever be asked for.

fn dummy_rand(dummy_thread: &mut DummyThread) -> u64 {
    let mut x = dummy_thread.state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;

    dummy_thread.state = x;

    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn dummy_word(dummy_thread: &mut DummyThread, out: &mut [u8], out_size: usize) -> usize {
    let r = dummy_rand(dummy_thread);

    let mut out_len = 6 + (r % 8) as usize;

    if out_len > out_size {
        out_len = out_size;
    }

    for i in 0..out_len {
        let c = dummy_rand(dummy_thread);

        out[i] = DUMMY_ALPHABET[(c % DUMMY_ALPHABET.len() as u64) as usize];
    }

    dummy_thread.pos += 1;

    out_len
}

#[unsafe(no_mangle)]
pub extern "C" fn global_init(
    _global_ctx: *mut generic_global_ctx_t,
    _thread_ctx: *mut *mut generic_thread_ctx_t,
    _hashcat_ctx: *mut c_void,
) -> bool {
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn global_term(
    _global_ctx: *mut generic_global_ctx_t,
    _thread_ctx: *mut *mut generic_thread_ctx_t,
    _hashcat_ctx: *mut c_void,
) {
}

#[unsafe(no_mangle)]
pub extern "C" fn global_keyspace(
    _global_ctx: *mut generic_global_ctx_t,
    _thread_ctx: *mut *mut generic_thread_ctx_t,
    _hashcat_ctx: *mut c_void,
) -> u64 {
    GENERIC_KEYSPACE_UNKNOWN
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_init(
    _global_ctx: *mut generic_global_ctx_t,
    thread_ctx: *mut generic_thread_ctx_t,
) -> bool {
    let dummy_thread = Box::new(DummyThread {
        state: DUMMY_SEED,
        pos: 0,
    });

    unsafe {
        (*thread_ctx).thrdata = Box::into_raw(dummy_thread) as *mut c_void;
    }

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_term(
    _global_ctx: *mut generic_global_ctx_t,
    thread_ctx: *mut generic_thread_ctx_t,
) {
    unsafe {
        let ptr = (*thread_ctx).thrdata as *mut DummyThread;

        if ptr.is_null() {
            return;
        }

        let _ = Box::from_raw(ptr);

        (*thread_ctx).thrdata = std::ptr::null_mut();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_next(
    _global_ctx: *mut generic_global_ctx_t,
    thread_ctx: *mut generic_thread_ctx_t,
    out_buf: *mut u8,
    out_size: c_int,
) -> c_int {
    unsafe {
        let dummy_thread = &mut *((*thread_ctx).thrdata as *mut DummyThread);

        // Never write more than out_size. hashcat hands out a pointer into the buffer it uploads, so
        // a long word does not get truncated, it lands on top of something else.

        let out_size = out_size as usize;

        let out = std::slice::from_raw_parts_mut(out_buf, out_size);

        dummy_word(dummy_thread, out, out_size) as c_int
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_seek(
    _global_ctx: *mut generic_global_ctx_t,
    thread_ctx: *mut generic_thread_ctx_t,
    offset: u64,
) -> bool {
    unsafe {
        let dummy_thread = &mut *((*thread_ctx).thrdata as *mut DummyThread);

        // Seeking forward only has to keep generating. Seeking back has to start over, because a
        // pseudo random sequence has no way to run in reverse.

        if offset < dummy_thread.pos {
            dummy_thread.state = DUMMY_SEED;
            dummy_thread.pos = 0;
        }

        let mut scratch = [0u8; 256];

        while dummy_thread.pos < offset {
            if dummy_word(dummy_thread, &mut scratch, 256) as c_int == GENERIC_RC_EOF {
                return false;
            }
        }
    }

    true
}

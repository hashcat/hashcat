#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
#[rustfmt::skip]
pub mod bindings;

/// common functions that are useful in Rust bridge implementations
pub mod common;

pub use bindings::{bridge_context_t, generic_io_t, generic_io_tmp_t, salt_t};
pub use common::*;

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
}

impl ThreadContext {
    pub fn get_raw_esalt(&self, salt_id: usize, is_selftest: bool) -> &generic_io_t {
        if is_selftest {
            &self.st_esalts[salt_id]
        } else {
            &self.esalts[salt_id]
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// test that bindings.rs exists by asserting some very basic things
    #[test]
    fn test_bindings_exists() {
        let ctx = bindings::generic_io_t {
            hash_buf: [0; 256],
            hash_len: 0,
            salt_buf: [0; 256],
            salt_len: 0,
        };
        assert_eq!(ctx.hash_len, 0);
        assert_eq!(ctx.salt_len, 0);
    }
}

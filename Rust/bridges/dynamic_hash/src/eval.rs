/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::collections::HashMap;

use crate::{DataDecoder, Expr, ExtraParams, OutputFormat};

use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::{Hmac, Mac};
use md2::Md2;
use md4::Md4;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

pub struct EvalContext(HashMap<String, Vec<u8>>);

impl EvalContext {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn set_var(&mut self, name: impl AsRef<str>, value: impl AsRef<[u8]>) {
        self.0
            .insert(String::from(name.as_ref()), Vec::from(value.as_ref()));
    }

    pub fn var(&self, name: impl AsRef<str>) -> Option<Vec<u8>> {
        let name = match name.as_ref() {
            "pass" => "p",
            "salt" => "s",
            other => other,
        };
        self.0.get(name).map(Vec::clone)
    }

    fn eval_number(&self, expr: &Expr) -> Result<u32, String> {
        match expr {
            Expr::Number(n) => Ok(*n),
            _ => String::from_utf8(self.eval(expr)?)
                .map_err(|e| e.to_string())?
                .parse::<u32>()
                .map_err(|e| e.to_string()),
        }
    }

    pub fn eval(&self, expr: &Expr) -> Result<Vec<u8>, String> {
        match expr {
            Expr::Call {
                name,
                arg,
                params: None,
                output_format,
            } => {
                let data = self.eval(arg)?;

                macro_rules! digest {
                    ($x:ty) => {
                        match output_format {
                            OutputFormat::Hex | OutputFormat::Default => {
                                hex::encode(<$x>::digest(data)).into_bytes()
                            }
                            OutputFormat::Binary => <$x>::digest(data).to_vec(),
                            OutputFormat::Base64 => {
                                BASE64_STANDARD.encode(<$x>::digest(data)).into_bytes()
                            }
                        }
                    };
                }

                Ok(match name.as_str() {
                    "upper" | "uc" => data.to_ascii_uppercase(),
                    "lower" | "lc" => data.to_ascii_lowercase(),
                    "hex" => Vec::from(hex::encode(data)),
                    "unhex" => hex::decode(data).map_err(|e| e.to_string())?,
                    "b64" | "base64" => Vec::from(BASE64_STANDARD.encode(data)),
                    "b64dec" | "b64decode" => {
                        BASE64_STANDARD.decode(data).map_err(|e| e.to_string())?
                    }
                    "utf16le" => match std::str::from_utf8(&data) {
                        Ok(s) => s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
                        Err(_) => vec![],
                    },

                    "md2" => digest!(Md2),
                    "md4" => digest!(Md4),
                    "md5" => digest!(Md5),
                    "sha1" => digest!(Sha1),
                    "sha224" => digest!(Sha224),
                    "sha256" => digest!(Sha256),
                    "sha384" => digest!(Sha384),
                    "sha512" => digest!(Sha512),
                    "sha3_224" => digest!(Sha3_224),
                    "sha3_256" => digest!(Sha3_256),
                    "sha3_384" => digest!(Sha3_384),
                    "sha3_512" => digest!(Sha3_512),

                    _ => unimplemented!(),
                })
            }

            Expr::Call {
                name,
                arg,
                params: Some(ExtraParams::Key(key_expr)),
                output_format,
            } => {
                let data = self.eval(arg)?;
                let key = self.eval(key_expr)?;

                macro_rules! hmac_digest {
                    ($x:ty) => {{
                        let mut hmac =
                            Hmac::<$x>::new_from_slice(&key).map_err(|e| e.to_string())?;
                        hmac.update(&data);
                        let output = hmac.finalize().into_bytes();
                        match output_format {
                            OutputFormat::Hex | OutputFormat::Default => {
                                hex::encode(output).into_bytes()
                            }
                            OutputFormat::Binary => output.to_vec(),
                            OutputFormat::Base64 => BASE64_STANDARD.encode(output).into_bytes(),
                        }
                    }};
                }

                Ok(match name.as_str() {
                    "hmac_md5" => hmac_digest!(Md5),
                    "hmac_sha1" => hmac_digest!(Sha1),
                    "hmac_sha224" => hmac_digest!(Sha224),
                    "hmac_sha256" => hmac_digest!(Sha256),
                    "hmac_sha384" => hmac_digest!(Sha384),
                    "hmac_sha512" => hmac_digest!(Sha512),
                    "hmac_sha3_224" => hmac_digest!(Sha3_224),
                    "hmac_sha3_256" => hmac_digest!(Sha3_256),
                    "hmac_sha3_384" => hmac_digest!(Sha3_384),
                    "hmac_sha3_512" => hmac_digest!(Sha3_512),

                    _ => unimplemented!(),
                })
            }

            Expr::Call {
                name,
                arg,
                params: Some(ExtraParams::RoundsSaltDklen(rounds, salt, dklen)),
                output_format,
            } => {
                let data = self.eval(arg)?;
                let rounds = self.eval_number(rounds)?;
                let salt = self.eval(salt)?;
                let dklen = self.eval_number(dklen)? as usize;

                macro_rules! pbkdf2_digest {
                    ($x:ty) => {{
                        let mut output = vec![0u8; dklen];
                        pbkdf2::pbkdf2_hmac::<$x>(&data, &salt, rounds, &mut output);
                        match output_format {
                            OutputFormat::Base64 | OutputFormat::Default => {
                                BASE64_STANDARD.encode(output).into_bytes()
                            }
                            OutputFormat::Hex => hex::encode(output).into_bytes(),
                            OutputFormat::Binary => output,
                        }
                    }};
                }

                Ok(match name.as_str() {
                    "pbkdf2_hmac_md5" => pbkdf2_digest!(Md5),
                    "pbkdf2_hmac_sha1" => pbkdf2_digest!(Sha1),
                    "pbkdf2_hmac_sha224" => pbkdf2_digest!(Sha224),
                    "pbkdf2_hmac_sha256" => pbkdf2_digest!(Sha256),
                    "pbkdf2_hmac_sha384" => pbkdf2_digest!(Sha384),
                    "pbkdf2_hmac_sha512" => pbkdf2_digest!(Sha512),
                    "pbkdf2_hmac_sha3_224" => pbkdf2_digest!(Sha3_224),
                    "pbkdf2_hmac_sha3_256" => pbkdf2_digest!(Sha3_256),
                    "pbkdf2_hmac_sha3_384" => pbkdf2_digest!(Sha3_384),
                    "pbkdf2_hmac_sha3_512" => pbkdf2_digest!(Sha3_512),

                    _ => unimplemented!(),
                })
            }

            Expr::Call {
                name,
                arg,
                params: Some(ExtraParams::StartLength(start, length)),
                ..
            } => {
                let data = self.eval(arg)?;

                Ok(match name.as_str() {
                    "cut" => data
                        .get(*start as usize..(*start + *length) as usize)
                        .ok_or_else(|| "cut: data is too short".to_string())?
                        .to_vec(),
                    _ => unimplemented!(),
                })
            }

            Expr::Call {
                name,
                arg,
                params: Some(ExtraParams::CostSalt(cost_expr, salt_expr)),
                ..
            } => {
                let data = self.eval(arg)?;
                let cost = self.eval_number(cost_expr)?;
                let salt = self.eval(salt_expr)?;

                macro_rules! to_arr16 {
                    ($x:expr) => {{
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice($x);
                        arr
                    }};
                }

                macro_rules! bcrypt {
                    ($version:expr) => {{
                        let bin_salt: [u8; 16] = match salt.len() {
                            16 => to_arr16!(&salt),
                            22 => match bcrypt::BASE_64.decode(salt) {
                                Ok(decoded_salt) if decoded_salt.len() == 16 => {
                                    to_arr16!(&decoded_salt)
                                }
                                _ => return Err("Failed to decode salt".to_string()),
                            },
                            _ => return Err("Invalid salt length".to_string()),
                        };
                        bcrypt::hash_with_salt(data, cost, bin_salt)
                            .map(|result| result.format_for_version($version).into_bytes())
                            .map_err(|e| e.to_string())?
                    }};
                }

                Ok(match name.as_str() {
                    "bcrypt" | "bcrypt2y" => bcrypt!(bcrypt::Version::TwoY),
                    "bcrypt2a" => bcrypt!(bcrypt::Version::TwoA),
                    "bcrypt2b" => bcrypt!(bcrypt::Version::TwoB),
                    "bcrypt2x" => bcrypt!(bcrypt::Version::TwoX),

                    _ => unimplemented!(),
                })
            }

            Expr::Concat(exprs) => {
                let mut v = vec![];
                for expr in exprs {
                    v.extend(self.eval(expr)?);
                }
                Ok(v)
            }

            Expr::Var((name, decoder)) => {
                let data = self
                    .var(name)
                    .ok_or_else(|| format!("Undefined variable '{}'", name))?;
                Ok(match decoder {
                    DataDecoder::None => data,
                    DataDecoder::Unhex => hex::decode(data).map_err(|e| e.to_string())?,
                    DataDecoder::B64Decode => {
                        BASE64_STANDARD.decode(data).map_err(|e| e.to_string())?
                    }
                })
            }

            Expr::Literal(v) => Ok(v.clone()),

            Expr::Number(_) => unreachable!(),
        }
    }
}

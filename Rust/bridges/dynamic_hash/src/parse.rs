/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use base64::{Engine, prelude::BASE64_STANDARD};
use std::fmt;

use crate::{DataDecoder, Expr, ExtraParams, OutputFormat};

const SUPPORTED_ALGORITHMS: &[&str] = &[
    "hex",
    "unhex",
    "b64",
    "base64",
    "b64dec",
    "b64decode",
    "upper",
    "uc",
    "lower",
    "lc",
    "cut",
    "utf16le",
    "md2",
    "md4",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "bcrypt",
    "bcrypt2a",
    "bcrypt2b",
    "bcrypt2x",
    "bcrypt2y",
];

#[derive(Debug)]
pub struct ParseError {
    pub msg: String,
    pub pos: usize,
}

pub fn parse(s: &str) -> ParseResult<Expr> {
    Parser::new(s).parse()
}

impl ParseError {
    fn new<E: fmt::Display>(e: E, pos: usize) -> Self {
        Self {
            msg: e.to_string(),
            pos,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parse error at position {}: {}", self.pos, self.msg)
    }
}

impl std::error::Error for ParseError {}

type ParseResult<T> = Result<T, ParseError>;

pub struct Parser {
    input: Vec<char>,
    pos: usize,
}

impl Parser {
    pub fn new(s: &str) -> Self {
        Parser {
            input: s.chars().collect(),
            pos: 0,
        }
    }

    pub fn parse(mut self) -> ParseResult<Expr> {
        self.skip_ws();
        let expr = self.parse_concat()?;
        self.skip_ws();
        if !self.eof() {
            return Err(ParseError::new(
                format!(
                    "Unexpected trailing characters starting with '{}'",
                    self.peek().unwrap()
                ),
                self.pos,
            ));
        }
        Ok(expr)
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.next_char();
            } else {
                break;
            }
        }
    }

    fn parse_concat(&mut self) -> ParseResult<Expr> {
        self.skip_ws();
        let mut parts = vec![self.parse_primary()?];
        self.skip_ws();
        while self.peek() == Some('.') {
            self.next_char();
            self.skip_ws();
            parts.push(self.parse_primary()?);
            self.skip_ws();
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expr::Concat(parts)
        })
    }

    fn unexpected_char<T>(&self, c: char) -> ParseResult<T> {
        Err(ParseError::new(
            format!("Unexpected character '{}'", c),
            self.pos,
        ))
    }

    fn parse_primary(&mut self) -> ParseResult<Expr> {
        self.skip_ws();
        match self.peek() {
            Some('"') => self.parse_string_literal(),
            Some('$') => self.parse_variable(),
            Some(c) if c.is_ascii_lowercase() => self.parse_call(),
            Some(c) => self.unexpected_char(c),
            None => Err(ParseError::new("Unexpected end of input", self.pos)),
        }
    }

    fn consume_char(&mut self, c: char) -> ParseResult<()> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseError::new(format!("Expected '{}'", c), self.pos))
        }
    }

    fn consume(&mut self, expected: &str) -> ParseResult<()> {
        self.skip_ws();
        let prefix: Vec<_> = expected.chars().collect();
        if self.input[self.pos..].starts_with(&prefix) {
            self.pos += expected.len();
            Ok(())
        } else {
            Err(ParseError::new(
                format!("Expected '{}'", expected),
                self.pos,
            ))
        }
    }

    fn parse_named_value(&mut self, name: &str, allow_numbers: bool) -> ParseResult<Expr> {
        self.skip_ws();
        self.consume(name)?;
        self.skip_ws();
        self.consume_char('=')?;
        self.skip_ws();
        let value = match self.peek() {
            Some('"') => self.parse_string_literal(),
            Some('$') => self.parse_variable(),
            Some('0'..='9') if allow_numbers => Ok(Expr::Number(self.parse_number()?)),
            Some(c) => self.unexpected_char(c),
            None => Err(ParseError::new("Unexpected end of input", self.pos)),
        }?;
        self.consume_char(',')?;
        Ok(value)
    }

    fn parse_number(&mut self) -> ParseResult<u32> {
        self.skip_ws();
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                s.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        if s.is_empty() {
            return Err(ParseError::new("Expected a number", self.pos));
        }
        s.parse::<u32>().map_err(|e| ParseError::new(e, self.pos))
    }

    fn parse_output_format(&mut self) -> ParseResult<(String, OutputFormat)> {
        self.consume_char(':')?;
        let format = self.parse_ident_name()?;
        match format.as_str() {
            "hex" => Ok((format, OutputFormat::Hex)),
            "bin" | "binary" | "raw" => Ok((format, OutputFormat::Binary)),
            "b64" | "base64" => Ok((format, OutputFormat::Base64)),
            _ => Err(ParseError::new(
                format!("Unsupported output format '{}'", format),
                self.pos,
            )),
        }
    }

    fn parse_bcrypt_params(&mut self) -> ParseResult<ExtraParams> {
        let mut cost = None;
        let mut salt = None;

        for _ in 0..2 {
            self.skip_ws();
            match self.peek() {
                Some('c') if cost.is_none() => {
                    cost = Some(self.parse_named_value("cost", true)?);
                }
                Some('s') if salt.is_none() => {
                    salt = Some(self.parse_named_value("salt", false)?);
                }
                Some(c) => {
                    return Err(ParseError::new(
                        format!("Expected 'cost=' or 'salt=', got '{}'", c),
                        self.pos,
                    ));
                }
                None => return Err(ParseError::new("Unexpected end of input", self.pos)),
            }
        }

        Ok(ExtraParams::CostSalt(
            Box::new(cost.unwrap()),
            Box::new(salt.unwrap()),
        ))
    }

    fn parse_pbkdf2_params(&mut self) -> ParseResult<ExtraParams> {
        let mut rounds = None;
        let mut salt = None;
        let mut dklen = None;

        for _ in 0..3 {
            self.skip_ws();
            match self.peek() {
                Some('r') if rounds.is_none() => {
                    rounds = Some(self.parse_named_value("rounds", true)?);
                }
                Some('s') if salt.is_none() => {
                    salt = Some(self.parse_named_value("salt", false)?);
                }
                Some('d') if dklen.is_none() => {
                    dklen = Some(self.parse_named_value("dklen", true)?);
                }
                Some(c) => {
                    return Err(ParseError::new(
                        format!("Expected 'rounds=' or 'salt=' or 'dklen=', got '{}'", c),
                        self.pos,
                    ));
                }
                None => return Err(ParseError::new("Unexpected end of input", self.pos)),
            }
        }

        Ok(ExtraParams::RoundsSaltDklen(
            Box::new(rounds.unwrap()),
            Box::new(salt.unwrap()),
            Box::new(dklen.unwrap()),
        ))
    }

    fn parse_call(&mut self) -> ParseResult<Expr> {
        let name = self.parse_ident_name()?;

        if !SUPPORTED_ALGORITHMS.contains(&name.as_str())
            && !SUPPORTED_ALGORITHMS.contains(&name.strip_prefix("hmac_").unwrap_or_default())
            && !SUPPORTED_ALGORITHMS
                .contains(&name.strip_prefix("pbkdf2_hmac_").unwrap_or_default())
        {
            return Err(ParseError::new(
                format!("Unsupported primitive '{}'", name),
                self.pos,
            ));
        }

        self.skip_ws();
        let (format_name, output_format) = if self.peek() == Some(':') {
            self.parse_output_format()?
        } else {
            (String::new(), OutputFormat::Default)
        };

        if output_format != OutputFormat::Default {
            if name.starts_with("bcrypt")
                || [
                    "hex",
                    "unhex",
                    "b64",
                    "base64",
                    "b64dec",
                    "b64decode",
                    "upper",
                    "uc",
                    "lower",
                    "lc",
                    "cut",
                    "utf16le",
                ]
                .contains(&name.as_str())
            {
                return Err(ParseError::new(
                    format!("Unsupported output format '{}' for '{}'", format_name, name),
                    self.pos,
                ));
            }
        }

        self.consume_char('(')?;

        let mut params = None;

        if name == "cut" {
            let start = self.parse_number()?;
            self.consume_char(',')?;
            let length = self.parse_number()?;
            self.consume_char(',')?;
            params = Some(ExtraParams::StartLength(start, length))
        };

        if name.starts_with("bcrypt") {
            params = Some(self.parse_bcrypt_params()?);
        };

        if name.starts_with("hmac_") {
            params = Some(ExtraParams::Key(Box::new(
                self.parse_named_value("key", false)?,
            )))
        };

        if name.starts_with("pbkdf2_hmac_") {
            params = Some(self.parse_pbkdf2_params()?);
        };

        let arg = self.parse_concat()?;

        self.consume_char(')')?;

        Ok(Expr::Call {
            arg: Box::new(arg),
            name,
            params,
            output_format,
        })
    }

    fn parse_ident_name(&mut self) -> ParseResult<String> {
        self.skip_ws();
        let mut s = String::new();
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() => s.push(c),
            Some(c) => {
                return Err(ParseError::new(
                    format!("Invalid start of identifier '{}'", c),
                    self.pos,
                ));
            }
            None => {
                return Err(ParseError::new(
                    "Unexpected end while parsing identifier",
                    self.pos,
                ));
            }
        }
        self.pos += 1;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                s.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(s)
    }

    fn parse_decoder(&mut self) -> ParseResult<DataDecoder> {
        self.consume_char(':')?;
        let format = self.parse_ident_name()?;
        match format.as_str() {
            "unhex" => Ok(DataDecoder::Unhex),
            "b64dec" | "b64decode" => Ok(DataDecoder::B64Decode),
            _ => Err(ParseError::new(
                format!("Unsupported decoder '{}'", format),
                self.pos,
            )),
        }
    }

    fn parse_variable(&mut self) -> ParseResult<Expr> {
        self.consume_char('$')?;
        let start = self.pos;
        let mut name = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }

        if name.is_empty() {
            return Err(ParseError::new("Expected variable name after '$'", start));
        }

        self.skip_ws();
        let decoder = if self.peek() == Some(':') {
            self.parse_decoder()?
        } else {
            DataDecoder::None
        };

        Ok(Expr::Var((name, decoder)))
    }

    fn parse_hex_escape(&mut self, data: &mut Vec<u8>) -> Result<(), ParseError> {
        fn hex_val(c: char, pos: usize) -> Result<u8, ParseError> {
            match c.to_ascii_lowercase() {
                '0'..='9' => Ok(c as u8 - b'0'),
                'a'..='f' => Ok(10 + c as u8 - b'a'),
                _ => Err(ParseError::new(format!("Invalid hex digit '{}'", c), pos)),
            }
        }

        let hi = self
            .next_char()
            .ok_or_else(|| ParseError::new("Incomplete hex escape sequence", self.pos))?;
        let lo = self
            .next_char()
            .ok_or_else(|| ParseError::new("Incomplete hex escape sequence", self.pos))?;

        let byte = (hex_val(hi, self.pos)? << 4) | hex_val(lo, self.pos)?;
        data.push(byte);

        Ok(())
    }

    fn parse_string_literal(&mut self) -> ParseResult<Expr> {
        self.consume_char('"')?;
        let mut data: Vec<u8> = Vec::new();
        loop {
            let c = match self.next_char() {
                Some(c) => c,
                None => return Err(ParseError::new("Unterminated string literal", self.pos)),
            };
            match c {
                '"' => break,
                '\\' => {
                    let escaped = match self.next_char() {
                        Some(e) => e,
                        None => {
                            return Err(ParseError::new(
                                "Unterminated escape in string literal",
                                self.pos,
                            ));
                        }
                    };
                    match escaped {
                        'n' => data.push(b'\n'),
                        'r' => data.push(b'\r'),
                        't' => data.push(b'\t'),
                        '\\' => data.push(b'\\'),
                        '"' => data.push(b'"'),
                        '0' => data.push(0),
                        'x' => self.parse_hex_escape(&mut data)?,
                        _ => self.unexpected_char(escaped)?,
                    }
                }
                other => {
                    let mut buf = [0u8; 4];
                    let encoded = other.encode_utf8(&mut buf).as_bytes();
                    data.extend_from_slice(encoded);
                }
            }
        }

        self.skip_ws();
        let decoder = if self.peek() == Some(':') {
            self.parse_decoder()?
        } else {
            DataDecoder::None
        };
        Ok(Expr::Literal(match decoder {
            DataDecoder::None => data,
            DataDecoder::Unhex => hex::decode(&data).map_err(|e| ParseError::new(e, self.pos))?,
            DataDecoder::B64Decode => BASE64_STANDARD
                .decode(&data)
                .map_err(|e| ParseError::new(e, self.pos))?,
        }))
    }
}

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use crate::{eval::EvalContext, parse::parse};

#[test]
fn test_cmyic2024_hash() {
    let algoritm = "bcrypt2b(cost=12,salt=$s,hmac_sha256:b64(key=$s,$p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "codebreaker");
    ctx.set_var("s", "iyvX.kDndyq/YiUvv7J.Ne");
    assert_eq!(
        String::from_utf8(ctx.eval(&ast).unwrap()).unwrap(),
        "$2b$12$iyvX.kDndyq/YiUvv7J.NePApguNMJG65lr2k7H0A7Y3d7LLc1tOS"
    );
}

#[test]
fn test_bcrypt_param_order() {
    let algoritm1 = r#"bcrypt(cost=4,salt=$s,"pass")"#;
    let algoritm2 = r#"bcrypt(salt=$s,cost=4,"pass")"#;
    let ast1 = parse(algoritm1).unwrap();
    let ast2 = parse(algoritm2).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s", "zhVYF6gIwKr7Eaxd6pGQ8O");
    let hash1 = String::from_utf8(ctx.eval(&ast1).unwrap()).unwrap();
    let hash2 = String::from_utf8(ctx.eval(&ast2).unwrap()).unwrap();
    assert_eq!(
        hash1,
        "$2y$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
    assert_eq!(hash1, hash2);
}

#[test]
fn test_bcrypt_variables() {
    let algoritm = "bcrypt(cost=$cost,salt=$mysalt,$mypass)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("cost", "4");
    ctx.set_var("mysalt", "zhVYF6gIwKr7Eaxd6pGQ8O");
    ctx.set_var("mypass", "pass");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2y$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
}

#[test]
fn test_bcrypt_string_literals() {
    let algoritm = r#"bcrypt(cost=$c,salt="zhVYF6gIwKr7Eaxd6pGQ8O","pass")"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("c", "4");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2y$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
}

#[test]
fn test_bcrypt_raw_salt() {
    let algoritm = "bcrypt(cost=4,salt=$s,$p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    let salt: [u8; 16] = [
        214, 53, 218, 31, 200, 138, 200, 203, 125, 25, 204, 223, 242, 178, 18, 249,
    ];
    ctx.set_var("s", salt);
    ctx.set_var("p", "pass");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2y$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
}

#[test]
fn test_bcrypt2a() {
    let algoritm = "bcrypt2a(cost=4,salt=$s,$p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s", "zhVYF6gIwKr7Eaxd6pGQ8O");
    ctx.set_var("p", "pass");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2a$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
}

#[test]
fn test_bcrypt2x() {
    let algoritm = "bcrypt2x(cost=4,salt=$s,$p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s", "zhVYF6gIwKr7Eaxd6pGQ8O");
    ctx.set_var("p", "pass");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2x$04$zhVYF6gIwKr7Eaxd6pGQ8O5Cr7VuSom10tmBgDHkuyswt0Dyy0NwC"
    );
}

#[test]
fn test_variable_unhex() {
    let algoritm = "$p:unhex";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "717765727479");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_variable_b64decode() {
    let algoritm = "$p:b64dec";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "cXdlcnR5");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_string_literal_unhex() {
    let algoritm = r#""717765727479":unhex"#;
    let ast = parse(algoritm).unwrap();
    let ctx = EvalContext::new();
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_string_literal_b64decode() {
    let algoritm = r#""cXdlcnR5":b64decode"#;
    let ast = parse(algoritm).unwrap();
    let ctx = EvalContext::new();
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_upper_and_cut() {
    let algoritm = "upper(cut(0,16,md5($p)))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "D8578EDF8458CE06");
}

#[test]
fn test_lower() {
    let algoritm = "lower(bcrypt(cost=4,salt=$s,$p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s", "zhVYF6gIwKr7Eaxd6pGQ8O");
    ctx.set_var("p", "pass");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2y$04$zhvyf6giwkr7eaxd6pgq8o5cr7vusom10tmbgdhkuyswt0dyy0nwc"
    );
}

#[test]
fn test_cut_right_half() {
    let algoritm = "cut(16,16,md5($p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "fbc5bb76a58c5ca4");
}

#[test]
fn test_hex_output_format() {
    let algoritm = "md5:hex($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "d8578edf8458ce06fbc5bb76a58c5ca4");
}

#[test]
fn test_base64_output_format() {
    let algoritm = "md5:b64($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "2FeO34RYzgb7xbt2pYxcpA==");
}

#[test]
fn test_binary_output_format() {
    let algoritm = "sha1:base64(sha1:bin($p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qhQg8YLoi55fh09vvnRZKR6PRgE=");
}

#[test]
fn test_mysql5() {
    let algoritm = r#""*".upper(sha1(sha1:binary($p)))"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "*AA1420F182E88B9E5F874F6FBE7459291E8F4601");
}

#[test]
fn test_md5x3() {
    let algoritm = "md5(md5(md5($p)))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "cf6ebf3453bf1877ee3f1dce7bd1ec19");
}

#[test]
fn test_hex() {
    let algoritm = "hex($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "717765727479");
}

#[test]
fn test_hex_unhex() {
    let algoritm = "unhex(hex($p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_b64() {
    let algoritm = "b64($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "cXdlcnR5");
}

#[test]
fn test_b64_and_b64decode() {
    let algoritm = "b64decode(base64($p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_sha224() {
    let algoritm = "sha224($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "5154aaa49392fb275ce7e12a7d3e00901cf9cf3ab10491673f97322f"
    );
}

#[test]
fn test_sha256() {
    let algoritm = "sha256($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5"
    );
}

#[test]
fn test_sha384() {
    let algoritm = "sha384($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "1ab60e110d41a9aac5e30d086c490819bfe3461b38c76b9602fe9686aa0aa3d28c63c96a1019e3788c40a14f4292e50f"
    );
}

#[test]
fn test_sha512() {
    let algoritm = "sha512($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "0dd3e512642c97ca3f747f9a76e374fbda73f9292823c0313be9d78add7cdd8f72235af0c553dd26797e78e1854edee0ae002f8aba074b066dfce1af114e32f8"
    );
}

#[test]
fn test_md4() {
    let algoritm = "md4($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "2a4bbeffd06c016ab4134cc7963496d2");
}

#[test]
fn test_sha3_224() {
    let algoritm = "sha3_224($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "13783bdfa4a63b202d9aa1992eccdd68a9fa5e44539273d8c2b797cd"
    );
}

#[test]
fn test_sha3_256() {
    let algoritm = "sha3_256($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "f171cbb35dd1166a20f99b5ad226553e122f3c0f2fe981915fb9e4517aac9038"
    );
}

#[test]
fn test_sha3_384() {
    let algoritm = "sha3_384($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "6729a614db5c5c97920e15501d361ba2f445758012e181af1c6300a99d9a951553fcc4e14aa614db164f61a758c6d6c9"
    );
}

#[test]
fn test_sha3_512() {
    let algoritm = "sha3_512($p)";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "f6d1015e17df348f2d84b3b603648ae4bd14011f4e5b82f885e45587bcad48947d37d64501dc965c0f201171c44b656ee28ed9a5060aea1f2a336025320683d6"
    );
}

#[test]
fn test_bcrypt_invalid_params() {
    assert!(parse("bcrypt(salt=4,$p)").is_err());
    assert!(parse("bcrypt(cost=$s,$p)").is_err());
    assert!(parse("bcrypt(cost=4,cost=$s,$p)").is_err());
    assert!(parse("bcrypt(salt=$s,salt=$s,$p)").is_err());
}

#[test]
fn test_hex_escapes_in_string_literals() {
    let algoritm = r#""\x71\x77\x65\x72\x74\x79""#;
    let ast = parse(algoritm).unwrap();
    let ctx = EvalContext::new();
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "qwerty");
}

#[test]
fn test_whitespace() {
    let algoritm =
        r#"bcrypt2b ( cost = 12, salt = $s , hmac_sha256 : b64 ( key = $s, $p ) ) . "3A" : unhex "#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "codebreaker");
    ctx.set_var("s", "iyvX.kDndyq/YiUvv7J.Ne");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "$2b$12$iyvX.kDndyq/YiUvv7J.NePApguNMJG65lr2k7H0A7Y3d7LLc1tOS:"
    );
}

#[test]
fn test_lc_uc() {
    let algoritm = r#"lc("UPPER").uc("lower")"#;
    let ast = parse(algoritm).unwrap();
    let ctx = EvalContext::new();
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "upperLOWER");
}

#[test]
fn test_pass_salt() {
    let algoritm = r#"$pass.":".$salt"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "p@ss");
    ctx.set_var("s", "s4lt");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "p@ss:s4lt");
}

#[test]
fn test_raw_output_format() {
    let algoritm = "sha1(sha1:raw($p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "aa1420f182e88b9e5f874f6fbe7459291e8f4601");
}

#[test]
fn test_md2() {
    let algoritm = "md2(cut(0,0,$p))";
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("p", "qwerty");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "8350e5a3e24c153df2275c9f80692773");
}

#[test]
fn test_pbkdf2_hmac_md5() {
    let algoritm =
        r#""md5:".$s1.":".$s2.":".pbkdf2_hmac_md5(rounds=$s1,salt=$s2:b64dec,dklen=$s3,$p)"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s1", "1000");
    ctx.set_var("s2", "NjAxMDY4MQ==");
    ctx.set_var("s3", "32");
    ctx.set_var("p", "hashcat");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "md5:1000:NjAxMDY4MQ==:a00DtIW9hP9voC85fmEA5uVhgdDx67nSPSm9yADHjkI="
    );
}

#[test]
fn test_pbkdf2_hmac_sha1() {
    let algoritm =
        r#""sha1:".$s1.":".$s2.":".pbkdf2_hmac_sha1(rounds=$s1,salt=$s2:b64dec,dklen=$s3,$p)"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s1", "1000");
    ctx.set_var("s2", "MTYwNTM4MDU4Mzc4MzA=");
    ctx.set_var("s3", "16");
    ctx.set_var("p", "hashcat");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "sha1:1000:MTYwNTM4MDU4Mzc4MzA=:aGghFQBtQ8+WVlMk5GEaMw=="
    );
}

#[test]
fn test_pbkdf2_hmac_sha256() {
    let algoritm =
        r#""sha256:".$s1.":".$s2.":".pbkdf2_hmac_sha256(rounds=$s1,salt=$s2:b64dec,dklen=$s3,$p)"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s1", "1000");
    ctx.set_var("s2", "NjI3MDM3");
    ctx.set_var("s3", "24");
    ctx.set_var("p", "hashcat");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk"
    );
}

#[test]
fn test_pbkdf2_hmac_sha512() {
    let algoritm =
        r#""sha512:".$s1.":".$s2.":".pbkdf2_hmac_sha512(rounds=$s1,salt=$s2:b64dec,dklen=$s3,$p)"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s1", "1000");
    ctx.set_var("s2", "NzY2");
    ctx.set_var("s3", "16");
    ctx.set_var("p", "hashcat");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(hash, "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA==");
}

#[test]
fn test_m40037() {
    let algoritm = r#"pbkdf2_hmac_sha256:hex(rounds=$s1,salt=$s2:unhex,dklen=$s3,utf16le(upper(md4(utf16le($p)))))"#;
    let ast = parse(algoritm).unwrap();
    let mut ctx = EvalContext::new();
    ctx.set_var("s1", "100");
    ctx.set_var("s2", "54188415275183448824");
    ctx.set_var("s3", "32");
    ctx.set_var("p", "hashcat");
    let hash = String::from_utf8(ctx.eval(&ast).unwrap()).unwrap();
    assert_eq!(
        hash,
        "55b530f052a9af79a7ba9c466dddcb8b116f8babf6c3873a51a3898fb008e123"
    );
}

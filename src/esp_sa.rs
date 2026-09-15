//! Parser and applier for `--esp-sa` CLI arguments.
//!
//! Format: `spi:enc_algo:enc_key_hex` (AEAD) or
//!         `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (non-AEAD).
//!
//! Examples:
//! - `0xDEADBEEF:null`
//! - `0x12345678:aes-128-cbc:0xAABBCC...:hmac-sha1-96:0xDDEEFF...`
//! - `0x12345678:aes-256-gcm:0xAABBCC...DDEE` (key = enc_key + salt)

#[cfg(feature = "esp-decrypt")]
use packet_dissector::dissectors::esp::{AuthenticationAlgorithm, EncryptionAlgorithm, EspSa};
use packet_dissector::registry::DissectorRegistry;

use crate::error::{DsctError, Result, ResultExt};

/// Parse hex string (with or without 0x prefix) into bytes.
///
/// Operates on raw bytes to avoid panics on non-ASCII input
/// (string slicing can panic at non-character-boundary indices).
fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);

    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(DsctError::invalid_argument(format!(
            "hex string has odd length: {}",
            raw.len()
        )));
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(raw.len() / 2);
    let (pairs, _) = raw.as_chunks::<2>();
    for (idx, chunk) in pairs.iter().enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| {
            DsctError::invalid_argument(format!("invalid hex at byte offset {}", idx * 2))
        })?;
        let lo = hex_val(chunk[1]).ok_or_else(|| {
            DsctError::invalid_argument(format!("invalid hex at byte offset {}", idx * 2 + 1))
        })?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

/// Parse SPI value (decimal or hex with 0x prefix).
fn parse_spi(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).context(format!("invalid SPI hex: {s}"))
    } else {
        s.parse::<u32>().context(format!("invalid SPI: {s}"))
    }
}

/// Parse a single `--esp-sa` argument into an SPI and its Security Association.
///
/// Accepted forms:
/// - `spi:null` / `spi:null:auth_algo:auth_key_hex`
/// - `spi:enc_algo:enc_key_hex` (AEAD ciphers)
/// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (cipher + separate auth)
#[cfg(feature = "esp-decrypt")]
fn parse_sa(arg: &str) -> Result<(u32, EspSa)> {
    use packet_dissector::dissectors::esp::{
        parse_authentication_algorithm, parse_encryption_algorithm,
    };

    let parts: Vec<&str> = arg.split(':').collect();
    if parts.len() < 2 {
        return Err(DsctError::invalid_argument(format!(
            "invalid --esp-sa format: expected 'spi:algo[:key[:auth_algo:auth_key]]', got '{arg}'"
        )));
    }

    let spi = parse_spi(parts[0]).context(format!("in --esp-sa '{arg}'"))?;
    let enc_algo_name = parts[1];

    /// Parse the optional trailing `auth_algo:auth_key_hex` pair.
    fn parse_auth(
        arg: &str,
        algo: &str,
        key_hex: &str,
    ) -> Result<(AuthenticationAlgorithm, Vec<u8>)> {
        let auth_key = parse_hex(key_hex).context(format!("auth key in --esp-sa '{arg}'"))?;
        let auth = parse_authentication_algorithm(algo, &auth_key)
            .map_err(|e| DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}")))?;
        Ok((auth, auth_key))
    }

    // null algorithm: no key needed (exactly 2 or 4 parts)
    if enc_algo_name == "null" {
        if parts.len() != 2 && parts.len() != 4 {
            return Err(DsctError::invalid_argument(format!(
                "--esp-sa '{arg}': 'null' requires exactly 2 parts (spi:null) or 4 parts (spi:null:auth_algo:auth_key), got {}",
                parts.len()
            )));
        }
        let (authentication, auth_key) = if parts.len() == 4 {
            parse_auth(arg, parts[2], parts[3])?
        } else {
            (AuthenticationAlgorithm::None, vec![])
        };

        return Ok((
            spi,
            EspSa {
                encryption: EncryptionAlgorithm::Null,
                enc_key: vec![],
                authentication,
                auth_key,
            },
        ));
    }

    // Non-null algorithms: exactly 3 parts (AEAD) or 5 parts (cipher + auth)
    if parts.len() != 3 && parts.len() != 5 {
        return Err(DsctError::invalid_argument(format!(
            "--esp-sa '{arg}': non-null algorithms require exactly 3 parts (spi:algo:key) or 5 parts (spi:algo:key:auth_algo:auth_key), got {}",
            parts.len()
        )));
    }

    let enc_key = parse_hex(parts[2]).context(format!("encryption key in --esp-sa '{arg}'"))?;

    let encryption = parse_encryption_algorithm(enc_algo_name, &enc_key)
        .map_err(|e| DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}")))?;

    // RFC 4106, Section 8.1 — an AEAD KEYMAT is the cipher key followed by a
    // 4-byte salt, which `parse_encryption_algorithm` has already lifted into
    // the algorithm. Keep only the cipher key, whose length must match the
    // cipher exactly.
    // <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
    let enc_key = match &encryption {
        EncryptionAlgorithm::Aes128Gcm { .. } => enc_key[..16].to_vec(),
        EncryptionAlgorithm::Aes192Gcm { .. } => enc_key[..24].to_vec(),
        EncryptionAlgorithm::Aes256Gcm { .. } => enc_key[..32].to_vec(),
        _ => enc_key,
    };

    let (authentication, auth_key) = if parts.len() == 5 {
        parse_auth(arg, parts[3], parts[4])?
    } else {
        (AuthenticationAlgorithm::None, vec![])
    };

    Ok((
        spi,
        EspSa {
            encryption,
            enc_key,
            authentication,
            auth_key,
        },
    ))
}

/// Parse `--esp-sa` arguments and apply them to the registry.
///
/// Each argument has the format:
/// - `spi:enc_algo:enc_key_hex` (for AEAD ciphers or null)
/// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (for non-AEAD ciphers)
///
/// The `null` algorithm requires no key: `spi:null`
#[cfg(feature = "esp-decrypt")]
pub fn parse_and_apply(registry: &DissectorRegistry, args: &[String]) -> Result<()> {
    for arg in args {
        let (spi, sa) = parse_sa(arg)?;
        registry.add_esp_sa(spi, sa);
    }
    Ok(())
}

/// No-op when esp-decrypt feature is not enabled.
#[cfg(not(feature = "esp-decrypt"))]
pub fn parse_and_apply(_registry: &DissectorRegistry, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(DsctError::invalid_argument(
            "--esp-sa requires the 'esp-decrypt' feature to be enabled",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "esp-decrypt")]
    mod sa {
        use super::super::parse_sa;
        use packet_dissector::dissectors::esp::{AuthenticationAlgorithm, EncryptionAlgorithm};

        #[test]
        fn null_without_key() {
            let (spi, sa) = parse_sa("0x1001:null").unwrap();
            assert_eq!(spi, 0x1001);
            assert_eq!(sa.encryption, EncryptionAlgorithm::Null);
            assert!(sa.enc_key.is_empty());
            assert_eq!(sa.authentication, AuthenticationAlgorithm::None);
        }

        #[test]
        fn null_with_auth() {
            let key = "0x".to_string() + &"aa".repeat(20);
            let (_, sa) = parse_sa(&format!("1:null:hmac-sha1-96:{key}")).unwrap();
            assert_eq!(sa.encryption, EncryptionAlgorithm::Null);
            assert_eq!(sa.authentication, AuthenticationAlgorithm::HmacSha1_96);
            assert_eq!(sa.auth_key, vec![0xAA; 20]);
        }

        #[test]
        fn cbc_with_auth() {
            let enc = "0x".to_string() + &"11".repeat(16);
            let auth = "0x".to_string() + &"22".repeat(20);
            let (_, sa) = parse_sa(&format!("2:aes-128-cbc:{enc}:hmac-sha1-96:{auth}")).unwrap();
            assert_eq!(sa.encryption, EncryptionAlgorithm::Aes128Cbc);
            assert_eq!(sa.enc_key, vec![0x11; 16]);
            assert_eq!(sa.auth_key, vec![0x22; 20]);
        }

        /// RFC 4106 KEYMAT is the cipher key followed by a 4-byte salt. The
        /// salt must be split off into the algorithm and never left in the
        /// cipher key, whose length must match the cipher.
        #[test]
        fn aead_keys_have_the_salt_split_off() {
            for (name, key_len) in [
                ("aes-128-gcm", 16usize),
                ("aes-192-gcm", 24),
                ("aes-256-gcm", 32),
            ] {
                let mut key = vec![0x33u8; key_len];
                key.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // salt
                let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();

                let (_, sa) = parse_sa(&format!("3:{name}:0x{hex}"))
                    .unwrap_or_else(|e| panic!("{name} must parse: {e:?}"));

                assert_eq!(sa.enc_key, vec![0x33; key_len], "{name}: enc_key length");
                let salt = match sa.encryption {
                    EncryptionAlgorithm::Aes128Gcm { salt }
                    | EncryptionAlgorithm::Aes192Gcm { salt }
                    | EncryptionAlgorithm::Aes256Gcm { salt } => salt,
                    other => panic!("{name}: expected an AEAD algorithm, got {other:?}"),
                };
                assert_eq!(salt, [0xDE, 0xAD, 0xBE, 0xEF], "{name}: salt");
            }
        }

        #[test]
        fn rejects_wrong_part_counts() {
            assert!(parse_sa("0x1001").is_err());
            assert!(parse_sa("0x1001:null:extra").is_err());
            let enc = "0x".to_string() + &"11".repeat(16);
            assert!(parse_sa(&format!("1:aes-128-cbc:{enc}:hmac-sha1-96")).is_err());
        }

        #[test]
        fn rejects_unknown_algorithm() {
            assert!(parse_sa("1:rot13:0x00").is_err());
        }
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0xDEAD").unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(parse_hex("DEAD").unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(parse_hex("0x01020304").unwrap(), vec![1, 2, 3, 4]);
        assert!(parse_hex("0xDEA").is_err()); // odd length
        assert!(parse_hex("0xGG").is_err()); // invalid hex
    }

    #[test]
    fn test_parse_spi() {
        assert_eq!(parse_spi("0xDEADBEEF").unwrap(), 0xDEADBEEF);
        assert_eq!(parse_spi("256").unwrap(), 256);
        assert_eq!(parse_spi("0x100").unwrap(), 256);
        assert!(parse_spi("abc").is_err());
    }
}

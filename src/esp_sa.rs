//! Parser and applier for `--esp-sa` CLI arguments.
//!
//! Format: `spi:enc_algo:enc_key_hex` (AEAD) or
//!         `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (non-AEAD),
//!         optionally followed by `:esn` or `:esn=HIGH` when the SA uses
//!         Extended Sequence Numbers.
//!
//! Examples:
//! - `0xDEADBEEF:null`
//! - `0x12345678:aes-128-cbc:0xAABBCC...:hmac-sha1-96:0xDDEEFF...`
//! - `0x12345678:aes-256-gcm:0xAABBCC...DDEE` (key = enc_key + salt)
//! - `0x12345678:aes-256-gcm:0xAABBCC...DDEE:esn=1` (ESN, high-order bits 1)

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

/// Split an optional trailing `esn` / `esn=HIGH` element off the SA parts.
///
/// Returns the high-order 32 bits of the 64-bit sequence number when the SA
/// uses Extended Sequence Numbers (`esn` alone means 0), `None` otherwise.
///
/// RFC 4303, Section 2.2.1 — "Only the low-order 32 bits of the sequence
/// number are transmitted in the plaintext ESP header of each packet", so a
/// stateless dissector has to be told the high-order bits. The AEAD
/// transforms include them in the AAD (RFC 4106, Section 5, Figure 4).
/// <https://www.rfc-editor.org/rfc/rfc4303#section-2.2.1>
/// <https://www.rfc-editor.org/rfc/rfc4106#section-5>
#[cfg(feature = "esp-decrypt")]
fn split_esn(arg: &str, parts: &mut Vec<&str>) -> Result<Option<u32>> {
    let Some(&last) = parts.last() else {
        return Ok(None);
    };
    let high = if last == "esn" {
        0
    } else if let Some(value) = last.strip_prefix("esn=") {
        parse_esn_high(value).ok_or_else(|| {
            DsctError::invalid_argument(format!(
                "--esp-sa '{arg}': invalid esn value '{value}': expected the high-order 32 bits of the sequence number as a decimal or 0x-prefixed hex u32"
            ))
        })?
    } else {
        return Ok(None);
    };
    parts.pop();
    Ok(Some(high))
}

/// Parse the `HIGH` of `esn=HIGH`: decimal or `0x`-prefixed hex digits only
/// (no sign, no whitespace), fitting in a `u32`.
#[cfg(feature = "esp-decrypt")]
fn parse_esn_high(value: &str) -> Option<u32> {
    let (digits, radix) = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => (hex, 16),
        None => (value, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

/// Reject `esn` on an SA whose algorithm never uses the high-order bits.
///
/// Only the GCM, CCM and ChaCha20-Poly1305 transforms put the ESN into their
/// AAD (RFC 4106, Section 5 / RFC 4309, Section 5 / RFC 7634, Section 2.1).
/// GMAC is not decrypted and ICVs are never verified, so for the other
/// algorithms the value would be silently ignored.
/// <https://www.rfc-editor.org/rfc/rfc4106#section-5>
/// <https://www.rfc-editor.org/rfc/rfc4309#section-5>
/// <https://www.rfc-editor.org/rfc/rfc7634#section-2.1>
#[cfg(feature = "esp-decrypt")]
fn check_esn_applies(arg: &str, encryption: &EncryptionAlgorithm, esn: Option<u32>) -> Result<()> {
    let uses_esn = matches!(
        encryption,
        EncryptionAlgorithm::Aes128Gcm { .. }
            | EncryptionAlgorithm::Aes192Gcm { .. }
            | EncryptionAlgorithm::Aes256Gcm { .. }
            | EncryptionAlgorithm::Aes128Ccm { .. }
            | EncryptionAlgorithm::Aes192Ccm { .. }
            | EncryptionAlgorithm::Aes256Ccm { .. }
            | EncryptionAlgorithm::ChaCha20Poly1305 { .. }
    );
    if esn.is_some() && !uses_esn {
        return Err(DsctError::invalid_argument(format!(
            "--esp-sa '{arg}': esn only applies to the GCM, CCM and ChaCha20-Poly1305 algorithms, which include the high-order sequence number bits in their AAD; remove it for this algorithm"
        )));
    }
    Ok(())
}

/// Parse a single `--esp-sa` argument into an SPI and its Security Association.
///
/// Accepted forms:
/// - `spi:null` / `spi:null:auth_algo:auth_key_hex`
/// - `spi:enc_algo:enc_key_hex` (AEAD ciphers)
/// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (cipher + separate auth)
///
/// Each form may end with `:esn` or `:esn=HIGH` (see [`split_esn`]).
#[cfg(feature = "esp-decrypt")]
fn parse_sa(arg: &str) -> Result<(u32, EspSa)> {
    use packet_dissector::dissectors::esp::{
        parse_authentication_algorithm, parse_encryption_algorithm,
    };

    let mut parts: Vec<&str> = arg.split(':').collect();
    let esn = split_esn(arg, &mut parts)?;
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
                "--esp-sa '{arg}': 'null' requires exactly 2 parts (spi:null) or 4 parts (spi:null:auth_algo:auth_key) before an optional esn element, got {}",
                parts.len()
            )));
        }
        check_esn_applies(arg, &EncryptionAlgorithm::Null, esn)?;
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
                esn,
            },
        ));
    }

    // Non-null algorithms: exactly 3 parts (AEAD) or 5 parts (cipher + auth)
    if parts.len() != 3 && parts.len() != 5 {
        return Err(DsctError::invalid_argument(format!(
            "--esp-sa '{arg}': non-null algorithms require exactly 3 parts (spi:algo:key) or 5 parts (spi:algo:key:auth_algo:auth_key) before an optional esn element, got {}",
            parts.len()
        )));
    }

    let enc_key = parse_hex(parts[2]).context(format!("encryption key in --esp-sa '{arg}'"))?;

    let encryption = parse_encryption_algorithm(enc_algo_name, &enc_key)
        .map_err(|e| DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}")))?;
    check_esn_applies(arg, &encryption, esn)?;

    // The KEYMAT of the GCM, CCM, GMAC, CTR and ChaCha20-Poly1305 transforms
    // is the cipher key followed by a salt or nonce, which
    // `parse_encryption_algorithm` has already lifted into the algorithm.
    // Keep only the cipher key, whose length must match the cipher exactly.
    // RFC 4106, Section 8.1 / RFC 3686, Section 5.1 / RFC 4309, Section 7.1 /
    // RFC 4543, Section 6 / RFC 7634, Section 2
    // <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
    // <https://www.rfc-editor.org/rfc/rfc3686#section-5.1>
    // <https://www.rfc-editor.org/rfc/rfc4309#section-7.1>
    // <https://www.rfc-editor.org/rfc/rfc4543#section-6>
    // <https://www.rfc-editor.org/rfc/rfc7634#section-2>
    let mut enc_key = enc_key;
    if let Some(key_len) = encryption.key_len() {
        enc_key.truncate(key_len);
    }

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
            esn,
        },
    ))
}

/// Parse `--esp-sa` arguments and apply them to the registry.
///
/// Each argument has the format:
/// - `spi:enc_algo:enc_key_hex` (for AEAD ciphers or null)
/// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (for non-AEAD ciphers)
///
/// optionally followed by `:esn` or `:esn=HIGH` for an SA with Extended
/// Sequence Numbers. The `null` algorithm requires no key: `spi:null`
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
                    EncryptionAlgorithm::Aes128Gcm { salt, .. }
                    | EncryptionAlgorithm::Aes192Gcm { salt, .. }
                    | EncryptionAlgorithm::Aes256Gcm { salt, .. } => salt,
                    other => panic!("{name}: expected an AEAD algorithm, got {other:?}"),
                };
                assert_eq!(salt, [0xDE, 0xAD, 0xBE, 0xEF], "{name}: salt");
            }
        }

        /// RFC 3686, Section 5.1 / RFC 4309, Section 7.1 / RFC 4543, Section 6 /
        /// RFC 7634, Section 2 — the KEYMAT of these transforms is the cipher
        /// key followed by a nonce or salt, which belongs to the algorithm and
        /// not to the cipher key.
        /// <https://www.rfc-editor.org/rfc/rfc3686#section-5.1>
        /// <https://www.rfc-editor.org/rfc/rfc4309#section-7.1>
        /// <https://www.rfc-editor.org/rfc/rfc4543#section-6>
        /// <https://www.rfc-editor.org/rfc/rfc7634#section-2>
        #[test]
        fn keymat_nonce_and_salt_are_split_off_the_cipher_key() {
            for (name, key_len, extra) in [
                ("aes-128-gcm-8", 16usize, 4usize),
                ("aes-256-gcm-12", 32, 4),
                ("aes-128-ctr", 16, 4),
                ("aes-192-ctr", 24, 4),
                ("aes-256-ctr", 32, 4),
                ("aes-128-ccm-8", 16, 3),
                ("aes-256-ccm-16", 32, 3),
                ("aes-128-gmac", 16, 4),
                ("chacha20-poly1305", 32, 4),
            ] {
                let mut key = vec![0x44u8; key_len];
                key.extend(std::iter::repeat_n(0xA5, extra));
                let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();

                let (_, sa) = parse_sa(&format!("4:{name}:0x{hex}"))
                    .unwrap_or_else(|e| panic!("{name} must parse: {e:?}"));

                assert_eq!(sa.enc_key, vec![0x44; key_len], "{name}: enc_key");
                assert_eq!(sa.encryption.key_len(), Some(key_len), "{name}: key_len");
                assert_eq!(sa.esn, None, "{name}: 32-bit sequence numbers");
            }
        }

        const GCM_KEYMAT: &str = "0x000102030405060708090a0b0c0d0e0fcafebabe";

        /// RFC 4303, Section 2.2.1 — only the low-order 32 bits of an ESN are
        /// on the wire; `:esn` declares an ESN SA whose high-order bits are 0.
        /// <https://www.rfc-editor.org/rfc/rfc4303#section-2.2.1>
        #[test]
        fn esn_without_value_means_high_bits_zero() {
            let (spi, sa) = parse_sa(&format!("0x1001:aes-128-gcm:{GCM_KEYMAT}:esn")).unwrap();
            assert_eq!(spi, 0x1001);
            assert_eq!(sa.esn, Some(0));
            assert_eq!(sa.enc_key.len(), 16);
        }

        #[test]
        fn esn_with_value() {
            let (_, sa) = parse_sa(&format!("1:aes-128-gcm:{GCM_KEYMAT}:esn=1")).unwrap();
            assert_eq!(sa.esn, Some(1));
            let (_, sa) = parse_sa(&format!("1:aes-128-gcm:{GCM_KEYMAT}:esn=0xFFFFFFFF")).unwrap();
            assert_eq!(sa.esn, Some(u32::MAX));
        }

        /// RFC 4309, Section 5 / RFC 7634, Section 2.1 — CCM and
        /// ChaCha20-Poly1305 build the same 12-octet ESN AAD as GCM.
        /// <https://www.rfc-editor.org/rfc/rfc4309#section-5>
        /// <https://www.rfc-editor.org/rfc/rfc7634#section-2.1>
        #[test]
        fn esn_with_ccm_and_chacha20_poly1305() {
            let ccm = "0x".to_string() + &"11".repeat(16 + 3);
            let (_, sa) = parse_sa(&format!("1:aes-128-ccm-16:{ccm}:esn=2")).unwrap();
            assert_eq!(sa.esn, Some(2));
            let chacha = "0x".to_string() + &"11".repeat(32 + 4);
            let (_, sa) = parse_sa(&format!("1:chacha20-poly1305:{chacha}:esn")).unwrap();
            assert_eq!(sa.esn, Some(0));
        }

        /// The other algorithms never use the high-order bits (GMAC is not
        /// decrypted, ICVs are not verified), so `esn` is rejected instead
        /// of being silently ignored.
        #[test]
        fn rejects_esn_for_algorithms_that_ignore_it() {
            let auth = "0x".to_string() + &"aa".repeat(20);
            let enc = "0x".to_string() + &"11".repeat(16);
            let ctr = "0x".to_string() + &"11".repeat(16 + 4);
            for arg in [
                "1:null:esn".to_string(),
                format!("1:null:hmac-sha1-96:{auth}:esn=1"),
                format!("2:aes-128-cbc:{enc}:hmac-sha1-96:{auth}:esn"),
                format!("2:aes-128-ctr:{ctr}:hmac-sha1-96:{auth}:esn"),
                format!("3:aes-128-gmac:{ctr}:esn"),
            ] {
                let err = parse_sa(&arg).expect_err(&arg);
                assert!(err.to_string().contains("esn only applies"), "{arg}: {err}");
            }
        }

        #[test]
        fn no_esn_suffix_means_32_bit_sequence_numbers() {
            let (_, sa) = parse_sa(&format!("1:aes-128-gcm:{GCM_KEYMAT}")).unwrap();
            assert_eq!(sa.esn, None);
        }

        #[test]
        fn rejects_malformed_esn() {
            for suffix in [
                "esn=",
                "esn=x",
                "esn=-1",
                "esn=+1",
                "esn=0x+1",
                "esn= 1",
                "esn=4294967296",
                "esn=0x",
                "esn=0x100000000",
                "ESN",
                "esn:esn",
            ] {
                let arg = format!("1:aes-128-gcm:{GCM_KEYMAT}:{suffix}");
                let err = parse_sa(&arg).expect_err(&arg);
                assert!(err.to_string().contains(&arg), "{arg}: {err}");
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

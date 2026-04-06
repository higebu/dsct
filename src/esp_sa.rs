//! Parser and applier for `--esp-sa` CLI arguments.
//!
//! Format: `spi:enc_algo:enc_key_hex` (AEAD) or
//!         `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (non-AEAD).
//!
//! Examples:
//! - `0xDEADBEEF:null`
//! - `0x12345678:aes-128-cbc:0xAABBCC...:hmac-sha1-96:0xDDEEFF...`
//! - `0x12345678:aes-256-gcm:0xAABBCC...DDEE` (key = enc_key + salt)

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
    for (idx, chunk) in raw.chunks_exact(2).enumerate() {
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

/// Parse `--esp-sa` arguments and apply them to the registry.
///
/// Each argument has the format:
/// - `spi:enc_algo:enc_key_hex` (for AEAD ciphers or null)
/// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` (for non-AEAD ciphers)
///
/// The `null` algorithm requires no key: `spi:null`
#[cfg(feature = "esp-decrypt")]
pub fn parse_and_apply(registry: &DissectorRegistry, args: &[String]) -> Result<()> {
    use packet_dissector::dissectors::esp::{
        AuthenticationAlgorithm, EspSa, parse_authentication_algorithm, parse_encryption_algorithm,
    };

    for arg in args {
        let parts: Vec<&str> = arg.split(':').collect();
        if parts.len() < 2 {
            return Err(DsctError::invalid_argument(format!(
                "invalid --esp-sa format: expected 'spi:algo[:key[:auth_algo:auth_key]]', got '{arg}'"
            )));
        }

        let spi = parse_spi(parts[0]).context(format!("in --esp-sa '{arg}'"))?;
        let enc_algo_name = parts[1];

        // null algorithm: no key needed (exactly 2 or 4 parts)
        if enc_algo_name == "null" {
            if parts.len() != 2 && parts.len() != 4 {
                return Err(DsctError::invalid_argument(format!(
                    "--esp-sa '{arg}': 'null' requires exactly 2 parts (spi:null) or 4 parts (spi:null:auth_algo:auth_key), got {}",
                    parts.len()
                )));
            }
            let (auth_algo, auth_key) = if parts.len() == 4 {
                let auth_key =
                    parse_hex(parts[3]).context(format!("auth key in --esp-sa '{arg}'"))?;
                let auth = parse_authentication_algorithm(parts[2], &auth_key).map_err(|e| {
                    DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}"))
                })?;
                (auth, auth_key)
            } else {
                (AuthenticationAlgorithm::None, vec![])
            };

            registry.add_esp_sa(
                spi,
                EspSa {
                    encryption: packet_dissector::dissectors::esp::EncryptionAlgorithm::Null,
                    enc_key: vec![],
                    authentication: auth_algo,
                    auth_key,
                },
            );
            continue;
        }

        // Non-null algorithms: exactly 3 parts (AEAD) or 5 parts (cipher + auth)
        if parts.len() != 3 && parts.len() != 5 {
            return Err(DsctError::invalid_argument(format!(
                "--esp-sa '{arg}': non-null algorithms require exactly 3 parts (spi:algo:key) or 5 parts (spi:algo:key:auth_algo:auth_key), got {}",
                parts.len()
            )));
        }

        let enc_key = parse_hex(parts[2]).context(format!("encryption key in --esp-sa '{arg}'"))?;

        let enc_algo = parse_encryption_algorithm(enc_algo_name, &enc_key)
            .map_err(|e| DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}")))?;

        // For GCM: key includes salt, extract just the enc_key portion
        let actual_enc_key = if enc_algo.is_aead() {
            match &enc_algo {
                packet_dissector::dissectors::esp::EncryptionAlgorithm::Aes128Gcm { .. } => {
                    enc_key[..16].to_vec()
                }
                packet_dissector::dissectors::esp::EncryptionAlgorithm::Aes256Gcm { .. } => {
                    enc_key[..32].to_vec()
                }
                _ => enc_key.clone(),
            }
        } else {
            enc_key
        };

        let (auth_algo, auth_key) = if parts.len() == 5 {
            let auth_key = parse_hex(parts[4]).context(format!("auth key in --esp-sa '{arg}'"))?;
            let auth = parse_authentication_algorithm(parts[3], &auth_key)
                .map_err(|e| DsctError::invalid_argument(format!("in --esp-sa '{arg}': {e}")))?;
            (auth, auth_key)
        } else {
            (AuthenticationAlgorithm::None, vec![])
        };

        registry.add_esp_sa(
            spi,
            EspSa {
                encryption: enc_algo,
                enc_key: actual_enc_key,
                authentication: auth_algo,
                auth_key,
            },
        );
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

//! Thread pool sizing helpers for parallel filter evaluation.

/// Environment variable name for overriding the thread count.
pub const THREADS_ENV: &str = "DSCT_THREADS";

/// Resolve the number of worker threads to use for parallel operations.
///
/// Precedence: explicit `flag` argument > [`THREADS_ENV`] environment variable >
/// physical CPU count (via `num_cpus::get_physical()`).
///
/// Returns `Err` if:
/// - `flag` is `Some(0)` (zero is not a valid thread count)
/// - The environment variable is set but cannot be parsed as `usize`
/// - The environment variable is set to `"0"`
pub fn resolve_thread_count(flag: Option<usize>) -> Result<usize, String> {
    resolve_thread_count_from(flag, std::env::var(THREADS_ENV).ok().as_deref())
}

/// Testable inner implementation that accepts the env value as a parameter.
///
/// This avoids `std::env::set_var` in tests (which is not safe to call from
/// multi-threaded test processes).
pub fn resolve_thread_count_from(
    flag: Option<usize>,
    env_value: Option<&str>,
) -> Result<usize, String> {
    if let Some(n) = flag {
        if n == 0 {
            return Err("thread count must be at least 1 (got 0)".to_string());
        }
        return Ok(n);
    }
    if let Some(val) = env_value {
        match val.parse::<usize>() {
            Ok(0) => {
                return Err(format!(
                    "{THREADS_ENV}=0 is not valid; thread count must be at least 1"
                ));
            }
            Ok(n) => return Ok(n),
            Err(_) => {
                return Err(format!(
                    "cannot parse {THREADS_ENV}={val:?} as a thread count"
                ));
            }
        }
    }
    Ok(num_cpus::get_physical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flag_takes_precedence() {
        assert_eq!(resolve_thread_count_from(Some(4), Some("2")), Ok(4));
    }

    #[test]
    fn env_used_when_no_flag() {
        assert_eq!(resolve_thread_count_from(None, Some("3")), Ok(3));
    }

    #[test]
    fn default_is_physical_cores() {
        let n = resolve_thread_count_from(None, None).unwrap();
        assert!(n >= 1);
    }

    #[test]
    fn flag_zero_is_error() {
        assert!(resolve_thread_count_from(Some(0), None).is_err());
    }

    #[test]
    fn env_zero_is_error() {
        assert!(resolve_thread_count_from(None, Some("0")).is_err());
    }

    #[test]
    fn env_unparsable_is_error() {
        assert!(resolve_thread_count_from(None, Some("abc")).is_err());
    }

    #[test]
    fn env_negative_is_error() {
        // "-1" cannot be parsed as usize
        assert!(resolve_thread_count_from(None, Some("-1")).is_err());
    }
}

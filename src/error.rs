//! Shared error types and helpers for dsct.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::num::ParseIntError;

use thiserror::Error;

type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Convenient result alias for dsct.
pub type Result<T> = std::result::Result<T, DsctError>;

/// High-level error classification used for exit codes and structured errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// User supplied invalid arguments or malformed input expressions.
    InvalidArguments,
    /// Referenced file does not exist.
    FileNotFound,
    /// Referenced file or device is not accessible due to permissions.
    PermissionDenied,
    /// Capture file format is invalid or unsupported.
    InvalidFormat,
    /// Generic I/O failure.
    Io,
    /// Any other error.
    Error,
}

impl ErrorCategory {
    /// Map the category to a process exit code.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidArguments => 2,
            Self::FileNotFound | Self::PermissionDenied => 3,
            Self::InvalidFormat => 4,
            Self::Io | Self::Error => 1,
        }
    }

    /// Map the category to a machine-readable error code string.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::FileNotFound => "file_not_found",
            Self::PermissionDenied => "permission_denied",
            Self::InvalidFormat => "invalid_format",
            Self::Io => "io_error",
            Self::Error => "error",
        }
    }
}

/// dsct's application error.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct DsctError {
    category: ErrorCategory,
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl DsctError {
    /// Construct a generic error message.
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Error,
            message: message.into(),
            source: None,
        }
    }

    /// Construct an invalid-argument error.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::InvalidArguments,
            message: message.into(),
            source: None,
        }
    }

    /// Construct an error with an explicit category and source.
    pub fn with_source(
        category: ErrorCategory,
        message: impl Into<String>,
        source: impl Into<BoxError>,
    ) -> Self {
        Self {
            category,
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// Wrap this error with additional context, preserving its category.
    pub fn context(self, message: impl Into<String>) -> Self {
        Self {
            category: self.category,
            message: message.into(),
            source: Some(Box::new(self)),
        }
    }

    /// Reclassify this error while preserving its message and source chain.
    pub fn reclassify(mut self, category: ErrorCategory) -> Self {
        self.category = category;
        self
    }

    /// Return the error category.
    pub fn category(&self) -> ErrorCategory {
        self.category
    }
}

impl From<io::Error> for DsctError {
    fn from(error: io::Error) -> Self {
        let category = match error.kind() {
            io::ErrorKind::NotFound => ErrorCategory::FileNotFound,
            io::ErrorKind::PermissionDenied => ErrorCategory::PermissionDenied,
            _ => ErrorCategory::Io,
        };
        Self::with_source(category, error.to_string(), error)
    }
}

impl From<serde_json::Error> for DsctError {
    fn from(error: serde_json::Error) -> Self {
        Self::with_source(ErrorCategory::Error, error.to_string(), error)
    }
}

impl From<toml::de::Error> for DsctError {
    fn from(error: toml::de::Error) -> Self {
        Self::with_source(ErrorCategory::Error, error.to_string(), error)
    }
}

impl From<ParseIntError> for DsctError {
    fn from(error: ParseIntError) -> Self {
        Self::with_source(ErrorCategory::Error, error.to_string(), error)
    }
}

impl From<packet_dissector_pcap::PcapError> for DsctError {
    fn from(error: packet_dissector_pcap::PcapError) -> Self {
        Self::with_source(ErrorCategory::InvalidFormat, error.to_string(), error)
    }
}

#[cfg(feature = "tui")]
impl From<rustix::io::Errno> for DsctError {
    fn from(error: rustix::io::Errno) -> Self {
        let io_error = io::Error::from_raw_os_error(error.raw_os_error());
        Self::from(io_error)
    }
}

/// Result extension methods for attaching context and classification.
pub trait ResultExt<T> {
    /// Add an outer error message while preserving the underlying cause chain.
    fn context(self, message: impl Into<String>) -> Result<T>;

    /// Reclassify an error as invalid arguments.
    fn invalid_argument(self) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: Into<DsctError>,
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|error| error.into().context(message))
    }

    fn invalid_argument(self) -> Result<T> {
        self.map_err(|error| error.into().reclassify(ErrorCategory::InvalidArguments))
    }
}

/// Format an error and its source chain as a single human-readable string.
pub fn format_error(error: &DsctError) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        rendered.push_str(": ");
        rendered.push_str(&next.to_string());
        source = next.source();
    }
    rendered
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdErrorTrait;

    // ---------- ErrorCategory ----------

    #[test]
    fn exit_code_covers_all_variants() {
        assert_eq!(ErrorCategory::InvalidArguments.exit_code(), 2);
        assert_eq!(ErrorCategory::FileNotFound.exit_code(), 3);
        assert_eq!(ErrorCategory::PermissionDenied.exit_code(), 3);
        assert_eq!(ErrorCategory::InvalidFormat.exit_code(), 4);
        assert_eq!(ErrorCategory::Io.exit_code(), 1);
        assert_eq!(ErrorCategory::Error.exit_code(), 1);
    }

    #[test]
    fn code_string_covers_all_variants() {
        assert_eq!(ErrorCategory::InvalidArguments.code(), "invalid_arguments");
        assert_eq!(ErrorCategory::FileNotFound.code(), "file_not_found");
        assert_eq!(ErrorCategory::PermissionDenied.code(), "permission_denied");
        assert_eq!(ErrorCategory::InvalidFormat.code(), "invalid_format");
        assert_eq!(ErrorCategory::Io.code(), "io_error");
        assert_eq!(ErrorCategory::Error.code(), "error");
    }

    #[test]
    fn display_matches_code() {
        assert_eq!(
            ErrorCategory::InvalidArguments.to_string(),
            "invalid_arguments"
        );
        assert_eq!(ErrorCategory::Io.to_string(), "io_error");
        assert_eq!(ErrorCategory::InvalidFormat.to_string(), "invalid_format");
    }

    // ---------- DsctError constructors ----------

    #[test]
    fn msg_defaults_to_error_category() {
        let err = DsctError::msg("boom");
        assert_eq!(err.category(), ErrorCategory::Error);
        assert_eq!(err.to_string(), "boom");
        assert!(StdErrorTrait::source(&err).is_none());
    }

    #[test]
    fn invalid_argument_sets_category() {
        let err = DsctError::invalid_argument("bad flag");
        assert_eq!(err.category(), ErrorCategory::InvalidArguments);
        assert_eq!(err.to_string(), "bad flag");
    }

    #[test]
    fn with_source_preserves_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::InvalidData, "io boom");
        let err = DsctError::with_source(ErrorCategory::Io, "wrapped", io_err);
        assert_eq!(err.category(), ErrorCategory::Io);
        assert_eq!(err.to_string(), "wrapped");
        let source = StdErrorTrait::source(&err).expect("source should be preserved");
        assert_eq!(source.to_string(), "io boom");
    }

    // ---------- context / reclassify ----------

    #[test]
    fn context_preserves_category() {
        let err = DsctError::invalid_argument("inner").context("outer");
        assert_eq!(err.category(), ErrorCategory::InvalidArguments);
        assert_eq!(err.to_string(), "outer");
    }

    #[test]
    fn context_chains_source() {
        let err = DsctError::msg("inner").context("outer");
        let source = StdErrorTrait::source(&err).expect("context should chain source");
        assert_eq!(source.to_string(), "inner");
    }

    #[test]
    fn reclassify_changes_only_category() {
        let err = DsctError::msg("message");
        let reclassified = err.reclassify(ErrorCategory::InvalidArguments);
        assert_eq!(reclassified.category(), ErrorCategory::InvalidArguments);
        assert_eq!(reclassified.to_string(), "message");
        assert!(StdErrorTrait::source(&reclassified).is_none());
    }

    #[test]
    fn reclassify_preserves_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::InvalidData, "root cause");
        let err = DsctError::with_source(ErrorCategory::Io, "wrapped", io_err)
            .reclassify(ErrorCategory::InvalidFormat);
        assert_eq!(err.category(), ErrorCategory::InvalidFormat);
        assert_eq!(err.to_string(), "wrapped");
        let source = StdErrorTrait::source(&err).expect("source should be preserved");
        assert_eq!(source.to_string(), "root cause");
    }

    // ---------- From impls ----------

    #[test]
    fn from_io_not_found_becomes_file_not_found() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let err: DsctError = io_err.into();
        assert_eq!(err.category(), ErrorCategory::FileNotFound);
        assert!(StdErrorTrait::source(&err).is_some());
    }

    #[test]
    fn from_io_permission_denied_becomes_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: DsctError = io_err.into();
        assert_eq!(err.category(), ErrorCategory::PermissionDenied);
    }

    #[test]
    fn from_io_other_kind_becomes_io() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "eof");
        let err: DsctError = io_err.into();
        assert_eq!(err.category(), ErrorCategory::Io);
    }

    #[test]
    fn from_serde_json_error_becomes_error_category() {
        let parse_err = serde_json::from_str::<serde_json::Value>("not json")
            .expect_err("invalid JSON should not parse");
        let err: DsctError = parse_err.into();
        assert_eq!(err.category(), ErrorCategory::Error);
        assert!(StdErrorTrait::source(&err).is_some());
    }

    #[test]
    fn from_toml_error_becomes_error_category() {
        let parse_err = toml::from_str::<toml::Value>("[unterminated")
            .expect_err("invalid TOML should not parse");
        let err: DsctError = parse_err.into();
        assert_eq!(err.category(), ErrorCategory::Error);
        assert!(StdErrorTrait::source(&err).is_some());
    }

    #[test]
    fn from_parse_int_error_becomes_error_category() {
        let parse_err: ParseIntError = "abc".parse::<u32>().expect_err("not a number should fail");
        let err: DsctError = parse_err.into();
        assert_eq!(err.category(), ErrorCategory::Error);
    }

    // ---------- ResultExt ----------

    #[test]
    fn result_ext_context_passes_through_ok() {
        let ok: std::result::Result<i32, io::Error> = Ok(42);
        let chained: Result<i32> = ok.context("should not trigger");
        assert_eq!(chained.expect("Ok should pass through"), 42);
    }

    #[test]
    fn result_ext_context_on_err_wraps_and_preserves_category() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let result: std::result::Result<(), io::Error> = Err(io_err);
        let err = result
            .context("while opening file")
            .expect_err("should be Err");
        assert_eq!(err.to_string(), "while opening file");
        // Category from io::Error translation must be preserved.
        assert_eq!(err.category(), ErrorCategory::FileNotFound);
        assert!(StdErrorTrait::source(&err).is_some());
    }

    #[test]
    fn result_ext_invalid_argument_reclassifies() {
        let io_err = io::Error::new(io::ErrorKind::InvalidData, "bad bytes");
        let result: std::result::Result<(), io::Error> = Err(io_err);
        let err = result.invalid_argument().expect_err("should be Err");
        assert_eq!(err.category(), ErrorCategory::InvalidArguments);
    }

    // ---------- format_error ----------

    #[test]
    fn format_error_single_error_has_no_suffix() {
        let err = DsctError::msg("just this");
        assert_eq!(format_error(&err), "just this");
    }

    #[test]
    fn format_error_joins_source_chain_with_colon_space() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "cannot find file");
        let err = DsctError::from(io_err).context("while reading config");
        let rendered = format_error(&err);
        assert!(
            rendered.starts_with("while reading config"),
            "unexpected prefix: {rendered}"
        );
        assert!(
            rendered.contains(": cannot find file"),
            "source chain not joined: {rendered}"
        );
    }
}

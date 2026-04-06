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

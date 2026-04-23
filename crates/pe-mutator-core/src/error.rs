use std::{error::Error as StdError, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    InvalidInput,
    Parse,
    Layout,
    Assembly,
    Encoding,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(message: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn illegal_argument(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::InvalidInput)
    }

    pub fn parse(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::Parse)
    }

    pub fn layout(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::Layout)
    }

    pub fn assembly(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::Assembly)
    }

    pub fn encoding(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::Encoding)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(message, ErrorKind::Internal)
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for Error {}

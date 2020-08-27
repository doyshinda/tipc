use errno::errno;

/// Error information about the attempted TIPC operation
/// # Example
/// ```
/// # use errno::{Errno, set_errno};
/// # use tipc::TipcError;
/// set_errno(Errno(113));
///
/// let e = TipcError::new("My error message");
/// assert_eq!(e.code(), 113);
/// assert_eq!(e.description(), "My error message: No route to host");
///```
#[derive(Debug)]
pub struct TipcError {
    code: i32,
    description: String,
}

impl TipcError {
    pub fn new(err_msg: &str) -> Self {
        let e = errno();
        TipcError {
            description: format!("{}: {}", err_msg, e),
            code: e.0,
        }
    }

    pub fn code(&self) -> i32 {
        self.code
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}
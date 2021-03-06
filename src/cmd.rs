use std::io::Error;
use std::process::{Command, Output};

const TIPC: &str = "tipc";

/// Set the host addr, can be omitted starting from Linux 4.17.
/// # Example
/// ```no_run
/// # use tipc::set_host_addr;
/// set_host_addr("1.1.1".to_string()).unwrap();
/// ```
pub fn set_host_addr(addr: String) -> Result<Output, Error> {
    Ok(Command::new(TIPC)
        .arg("node")
        .arg("set")
        .arg("addr")
        .arg(&addr)
        .output()?)
}

/// Attach TIPC to an interface to allow communication with other
/// nodes on the network.
/// # Example
/// ```no_run
/// # use tipc::attach_to_interface;
/// attach_to_interface("eth0").unwrap();
/// ```
pub fn attach_to_interface(iface: &str) -> Result<Output, Error> {
    Ok(Command::new(TIPC)
        .arg("bearer")
        .arg("enable")
        .arg("media")
        .arg("eth")
        .arg("device")
        .arg(iface)
        .output()?)
}

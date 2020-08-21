#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use std::process::Command;
use std::os::raw::{c_void, c_int};

const TIPC: &'static str = "tipc";

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


// TODO: change `addr` to a custom type
pub fn set_host_addr(addr: String) {
    let cmd_output = Command::new(TIPC)
                        .arg("node")
                        .arg("set")
                        .arg("addr")
                        .arg(&addr)
                        .output()
                        .expect("Failed to set node addr");
    println!("Output: {:?}", cmd_output.stdout);
}

pub fn attach_to_interface(iface: &str) {
    let cmd_output = Command::new(TIPC)
                        .arg("bearer")
                        .arg("enable")
                        .arg("media")
                        .arg("eth")
                        .arg("device")
                        .arg(iface)
                        .output()
                        .expect("Failed to attach to interface");
    println!("Output: {:?}", cmd_output);
}

pub enum SockType {
    SockRDM = __socket_type_SOCK_RDM as isize,
}

pub struct TipcConn {
    socket: c_int,
}

pub struct TipcError {
    pub description: String,
}

impl TipcError {
    pub fn new(err_msg: &str) -> Self {
        TipcError {
            description: err_msg.to_string(),
        }
    }
}

type TipcResult<T> = Result<T, TipcError>;

impl TipcConn {
    pub fn new(socktype: SockType) -> TipcResult<Self> {
        let socket = unsafe { tipc_socket(socktype as i32) };
        if socket < 0 {
            return Err(TipcError::new("Unable to initialize socket"))
        }
        Ok(Self {socket})
    }

    pub fn broadcast(self, msg: &str, nameseq_type: u32) {
        unsafe {
            // let socket = tipc_socket(__socket_type_SOCK_RDM as i32);
            let addr = tipc_addr {
                type_: nameseq_type,
                instance: 0,
                node: 0,
            };
            // let msg_ptr: *const c_void = s.as_ptr() as *const c_void;
            let bytes_sent = tipc_mcast(
                self.socket,
                msg.as_ptr() as *const c_void,
                msg.len() as size_t,
                &addr,
            );
            println!("bytes sent: {:?}", bytes_sent);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

//! Linux [TIPC](http://tipc.io/) bindings
//!
//! This library provides basic support for
//! Linux Transparent Inter Process Communication (TIPC).
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use std::process::Command;
use std::os::raw::{c_void, c_int};
use crossbeam_channel::Sender;

// Include the generated C-API bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const TIPC: &'static str = "tipc";
const MAX_RECV_SIZE: usize = 66000;

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
    SOCK_STREAM = __socket_type_SOCK_STREAM as isize,
    SOCK_DGRAM = __socket_type_SOCK_DGRAM as isize,
    SOCK_SEQPACKET = __socket_type_SOCK_SEQPACKET as isize,
    SOCK_RDM = __socket_type_SOCK_RDM as isize,
}

pub struct TipcConn {
    socket: c_int,
}

#[derive(Debug)]
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
    /// Create a new conn with a specific `SockType`.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_RDM).unwrap();
    /// ```
    pub fn new(socktype: SockType) -> TipcResult<Self> {
        let socket = unsafe { tipc_socket(socktype as i32) };
        if socket < 0 {
            return Err(TipcError::new("Unable to initialize socket"))
        }
        Ok(Self {socket})
    }

    /// Broadcast a message to every node bound to `nameseq_type`. Returns the number
    /// of bytes sent.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_RDM).unwrap();
    /// if let Ok(bytes_sent) = conn.broadcast("Testing from Rust", 88888u32) {
    ///     println!("successfully sent {} bytes", bytes_sent);
    /// }
    /// ```
    pub fn broadcast(&self, msg: &str, nameseq_type: u32) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: nameseq_type,
            instance: 0,
            node: 0,
        };
        let bytes_sent = unsafe {
            tipc_mcast(
                self.socket,
                msg.as_ptr() as *const c_void,
                msg.len() as size_t,
                &addr,
            )
        };
        if bytes_sent < 0 {
            return Err(TipcError::new("Error broadcasting msg"));
        }
        Ok(bytes_sent)
    }

    /// Bind to an address.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_RDM).unwrap();
    /// if let Err(e) = conn.bind(88888, 69, 69, 0) {
    ///     panic!("Error binding to 88888-69-69: {:?}", e);
    /// }
    /// ```
    pub fn bind(&self, server_type: u32, lower: u32, upper: u32, scope: u32) -> TipcResult<()> {
        let r = unsafe { tipc_bind(self.socket, server_type, lower, upper, scope) };
        if r < 0 {
            return Err(TipcError::new("Error binding to socket address"));
        }

        Ok(())
    }

    /// Starts a loop, receiving data from the socket and sending
    /// it to the `tx` channel.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_RDM).unwrap();
    /// conn.bind(88888, 69, 69, 0).expect("Unable to bind to address");
    ///
    /// let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();

    /// thread::spawn(move || {
    ///     loop {
    ///         match r.recv() {
    ///             Ok(m) => println!("{}", str::from_utf8(&m).unwrap()),
    ///             Err(e) => panic!("error reading: {:?}", e),
    ///         }
    ///     }
    /// });
    ///
    /// conn.recv(s)
    pub fn recv(&self, tx: Sender<Vec<u8>>) {
        let mut buf: [u8; MAX_RECV_SIZE] = [0; MAX_RECV_SIZE];
        loop {
            let msg_size = unsafe {
                 tipc_recv(
                    self.socket,
                    &mut buf as *mut _ as *mut c_void,
                    MAX_RECV_SIZE as size_t,
                    false,
                )
            };
            let msg = buf[0..msg_size as usize].to_vec();
            if let Err(e) = tx.send(msg) {
                println!("Send error: {:?}", e);
            }
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

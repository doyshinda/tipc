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

    /// Connect to a connection oriented socket.
    /// # Example
    /// ```
    /// ```
    pub fn connect(&self, type_: u32, instance: u32, node: u32) -> TipcResult<()> {
        let addr = tipc_addr {type_, instance, node};
        let r = unsafe { tipc_connect(self.socket, &addr) };
        if r < 0 {
            return Err(TipcError::new("Unable to connect to socket"));
        }

        Ok(())
    }

    /// Listen for incoming connections.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_SEQPACKET).unwrap();
    /// conn.bind(88888, 69, 69, 0).expect("Unable to bind to address");
    /// conn.listen(1).unwrap();
    /// ```
    pub fn listen(&self, backlog: i32) -> TipcResult<()> {
        let r = unsafe { tipc_listen(self.socket, backlog) };
        if r < 0 {
            return Err(TipcError::new("Unable to listen for new connections"));
        }

        Ok(())
    }

    /// Accept a connection on a listening socket.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_SEQPACKET).unwrap();
    /// conn.bind(88888, 69, 69, 0).expect("Unable to bind to address");
    /// conn.listen(1).unwrap();
    /// let new_conn = conn.accept().unwrap();
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
    /// new_conn.recv(s);
    /// ```
    pub fn accept(&self) -> TipcResult<Self> {
        let mut addr = tipc_addr {
            type_: 0,
            instance: 0,
            node: 0,
        };
        let s = unsafe { tipc_accept(self.socket, &mut addr) };
        return Ok(Self{socket: s});
    }

    /// Send data on a connected socket.
    /// # Example
    /// ```
    /// let conn = TipcConn::new(SockType::SOCK_SEQPACKET).unwrap();
    /// conn.connect(88888, 69, 0).unwrap();
    /// assert_eq!(conn.send(b"foo").unwrap(), 3);
    /// ```
    pub fn send(&self, data: &[u8]) -> TipcResult<i32> {
        let r = unsafe {
            tipc_send(
                self.socket,
                data as *const _ as *const c_void,
                data.len() as u64,
            )
        };
        if r < 0 {
            return Err(TipcError::new("unable send data"));
        }

        return Ok(r)
    }

    /// Broadcast data to every node bound to `nameseq_type`. Returns the number
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
            // TODO: Handle other side closing connection
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

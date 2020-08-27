//! Linux [Transparent Inter Process Communication (TIPC)][1] bindings for Rust
//!
//! [1]: http://tipc.io/
//!
//! This library provides bindings for some of the more common TIPC operations.
//!
//! ## Enable tipc kernel module
//! ```sh
//! sudo modprobe tipc
//! ```
//!
//! ## Create a new socket
//! ```ignore
//! use tipc::{TipcConn, SockType};
//! let conn = TipcConn::new(SockType::SockRdm).unwrap();
//! ```
//!
//! ## Bind to an address
//! ```ignore
//! use tipc::{TipcConn, SockType, TipcScope};
//! let conn = TipcConn::new(SockType::SockRdm).unwrap();
//!
//! let addr = tipc::bind_address(12345, 0, 0, TipcScope::Cluster);
//! conn.bind(&addr).expect("Unable to bind to address");
//! ```
//!
//! ## Join a group
//! Note: Joining a group automatically binds to an address and creates the group
//! if it doesn't already exist.
//! ```ignore
//! use tipc::{TipcConn, SockType, TipcScope};
//! let conn = TipcConn::new(SockType::SockRdm).unwrap();
//!
//! let addr = tipc::join_address(12345, 1, TipcScope::Cluster);
//! conn.join(&addr).expect("Unable to join group");
//! ```
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use std::os::raw::{c_void, c_int};
use crossbeam_channel::Sender;

pub mod address;
mod bindings;
mod cmd;
mod error;
mod group;

pub use address::*;
use bindings::*;
pub use cmd::{set_host_addr, attach_to_interface};
pub use group::{GroupMessage, Membership};
pub use error::TipcError;

pub const MAX_MSG_SIZE: usize = TIPC_MAX_USER_MSG_SIZE as usize;


/// TIPC socket type to be used.
#[derive(Clone, Copy)]
pub enum SockType {
    SockStream = __socket_type_SOCK_STREAM as isize,
    SockDgram = __socket_type_SOCK_DGRAM as isize,
    SockSeqpacket = __socket_type_SOCK_SEQPACKET as isize,
    SockRdm = __socket_type_SOCK_RDM as isize,
}

type TipcResult<T> = Result<T, TipcError>;

/// Wrapper around a socket to provide convenience functions for binding, sending data, etc.
#[derive(Debug)]
pub struct TipcConn {
    socket: c_int,
    socket_ref: u32,
    node_ref: u32,
}

impl Drop for TipcConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl TipcConn {
    pub fn socket_ref(&self) -> u32 {
        self.socket_ref
    }

    pub fn node_ref(&self) -> u32 {
        self.node_ref
    }

    fn close(&self) {
        unsafe { tipc_close(self.socket) };
    }

    /// Create a new conn of a specific socket type.
    pub fn new(socktype: SockType) -> TipcResult<Self> {
        let socket = unsafe { tipc_socket(socktype as i32) };
        if socket < 0 {
            return Err(TipcError::new("Unable to initialize socket"))
        }

        let (socket_ref, node_ref) = socket_and_node_refs(socket)?;
        Ok(Self {socket, socket_ref, node_ref})
    }

    /// Set the socket to be non-blocking. This causes socket calls to return a
    /// TipcError with EAGAIN | EWOULDBLOCK error code set when it's not possible
    /// to send/recv on the socket.
    pub fn set_sock_non_block(&mut self) -> TipcResult<()> {
        self.socket = unsafe { tipc_sock_non_block(self.socket) };
        Ok(())
    }

    /// Connect a stream socket.
    pub fn connect(&self, addr: &TipcAddr) -> TipcResult<()> {
        let addr = tipc_addr {
            type_: addr.service_type,
            instance: addr.instance,
            node: addr.node,
            scope: addr.scope as u32,
        };
        let r = unsafe { tipc_connect(self.socket, &addr) };
        if r < 0 {
            return Err(TipcError::new("Error connecting socket"));
        }

        Ok(())
    }

    /// Listen for incoming connections on a stream socket.
    /// See Linux [listen(2)](https://man7.org/linux/man-pages/man2/listen.2.html)
    /// for definition of `backlog`.
    pub fn listen(&self, backlog: i32) -> TipcResult<()> {
        let r = unsafe { tipc_listen(self.socket, backlog) };
        if r < 0 {
            return Err(TipcError::new("Unable to listen for new connections"));
        }

        Ok(())
    }

    /// Accept a connection on a listening socket.
    pub fn accept(&self) -> TipcResult<Self> {
        let mut addr = tipc_addr {
            type_: 0,
            instance: 0,
            node: 0,
            scope: 0,
        };
        let socket = unsafe { tipc_accept(self.socket, &mut addr) };
        if socket < 0 {
            return Err(TipcError::new("Error accepting a connection"));
        }

        let (socket_ref, node_ref) = socket_and_node_refs(socket)?;
        return Ok(Self {socket, socket_ref, node_ref});
    }

    /// Send data to the socket. Returns the number of bytes sent.
    pub fn send(&self, data: &[u8]) -> TipcResult<i32> {
        let r = unsafe {
            tipc_send(
                self.socket,
                data.as_ptr() as *const c_void,
                data.len() as u64,
            )
        };
        if r < 0 {
            return Err(TipcError::new("Send error"));
        }

        return Ok(r)
    }

    /// Broadcast data to every node in a group. Returns the number
    /// of bytes sent.
    pub fn broadcast(&self, data: &[u8]) -> TipcResult<i32> {
        self.send(data)
    }

    /// Anycast data to a random node bound to the `service_type` set in `addr`. TIPC
    /// protocol will round-robin available hosts. If this call is made in a group, TIPC will
    /// also take into consideration the destination's load, possible passing it by to pick
    /// another node.
    ///
    /// The `instance` and `node` values in `TipcAddr` are ignored.
    pub fn anycast(&self, data: &[u8], addr: &TipcAddr) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: addr.service_type,
            instance: 0,
            node: 0,
            scope: addr.scope as u32,
        };
        let bytes_sent = unsafe {
            tipc_sendto(
                self.socket,
                data.as_ptr() as *const c_void,
                data.len() as size_t,
                &addr,
            )
        };
        if bytes_sent < 0 {
            return Err(TipcError::new("Anycast error"));
        }
        Ok(bytes_sent)
    }

    /// Unicast data to a specific socket address. Returns the number of bytes sent.
    ///
    /// When unicasting, `instance` field in `addr` is used to represent the dst socket
    /// ref, while `node` represents the dst node id. The `service_type` field is ignored.
    pub fn unicast(&self, data: &[u8], addr: &TipcAddr) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: 0,
            instance: addr.instance,
            node: addr.node,
            scope: addr.scope as u32,
        };

        let bytes_sent = self.send_to(data, &addr);
        if bytes_sent < 0 {
            return Err(TipcError::new("Unicast error"));
        }
        Ok(bytes_sent)
    }

    /// Multicast data to every node bound to the address and range set in `addr`.
    /// Returns the number of bytes sent.
    ///
    /// The `instance` field is used to represent the lower value in the range and
    /// `node` field is the upper value in the range.
    pub fn multicast(&self, data: &[u8], addr: &TipcAddr) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: addr.service_type,
            instance: addr.instance,
            node: addr.node,
            scope: addr.scope as u32,
        };
        let bytes_sent = self.send_to(data, &addr);
        if bytes_sent < 0 {
            return Err(TipcError::new("Multicast error"));
        }
        Ok(bytes_sent)
    }

    /// Join a group.
    ///
    /// The `service_type` field represents the group_id, and the `instance` field represents
    /// the member id. The `node` field is ignored.
    pub fn join(&self, addr: &TipcAddr) -> TipcResult<()> {
        let mut addr = tipc_addr {
            type_: addr.service_type,
            instance: addr.instance,
            node: 0,
            scope: addr.scope as u32,
        };

        let r = unsafe { tipc_join(self.socket, &mut addr, true, false) };
        if r < 0 {
            return Err(TipcError::new("Unable to join group"));
        }

        Ok(())
    }

    /// Leave a group.
    pub fn leave(&self) -> TipcResult<()> {
        let r = unsafe { tipc_leave(self.socket) };
        if r < 0 {
            return Err(TipcError::new("Leave error"));
        }

        return Ok(())
    }

    /// Bind to an address and range.
    pub fn bind(&self, addr: &TipcAddr) -> TipcResult<()> {
        let r = unsafe {
            tipc_bind(self.socket, addr.service_type, addr.instance, addr.node, addr.scope as u32)
        };
        if r < 0 {
            return Err(TipcError::new("Error binding to socket address"));
        }

        Ok(())
    }

    /// Starts an endless loop, receiving data from the socket and sending
    /// it to the transmission side of an unbounded channel.
    /// # Example
    /// ```ignore
    /// let conn = TipcConn::new(SockType::SockRdm).unwrap();
    /// let addr = TipcAddr{service_type: 88888, instance: 0, node: 10, scope: TipcScope::CLUSTER};
    /// conn.bind(&addr).expect("Unable to bind to address");
    ///
    /// let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    ///
    /// // Handle socket data from the receiving end of the channel
    /// thread::spawn(move || {
    ///     loop {
    ///         match r.recv() {
    ///             Ok(m) => println!("{}", str::from_utf8(&m).unwrap()),
    ///             Err(e) => panic!("error reading: {:?}", e),
    ///         }
    ///     }
    /// });
    ///
    /// conn.recv_loop(s)
    pub fn recv_loop(&self, tx: Sender<Vec<u8>>) -> TipcResult<()>{
        let mut buf: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE];
        loop {
            let msg_size = self.recv_buf(&mut buf)?;
            let msg = buf[0..msg_size as usize].to_vec();
            if let Err(e) = tx.send(msg) {
                println!("Send error: {:?}", e);
            }
        }
    }

    /// Receive data from a socket, copying it to the passed in buffer. Returns
    /// the number of bytes received.
    /// # Example
    /// ```ignore
    /// let conn = TipcConn::new(SockType::SockRdm).unwrap();
    /// let addr = TipcAddr{service_type: 88888, instance: 0, node: 10, scope: TipcScope::Cluster};
    /// conn.bind(&addr).expect("Unable to bind to address");
    /// let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
    /// loop {
    ///     let msg_size = conn.recv_buf(&mut buf).unwrap();
    ///     println!("{}", std::str::from_utf8(&buf[0..msg_size as usize]).unwrap())
    /// }
    pub fn recv_buf(&self, buf: &mut [u8; MAX_MSG_SIZE]) -> TipcResult<i32> {
        let msg_size = unsafe {
             tipc_recv(
                self.socket,
                buf.as_ptr() as *mut c_void,
                MAX_MSG_SIZE as size_t,
                false,
            )
        };
        if msg_size < 0 {
            return Err(TipcError::new("Receive error"));
        }

        return Ok(msg_size);
    }

    /// Starts an endless loop, receiving data & group membership messages from the socket
    /// and sending it to the transmission side of an unbounded channel.
    /// # Example
    /// ```ignore
    /// let conn = TipcConn::new(SockType::SockRdm).unwrap();
    /// let addr = TipcAddr{service_type: 88888, instance: 0, node: 10, scope: TipcScope::CLUSTER};
    /// conn.bind(&addr).expect("Unable to bind to address");
    ///
    /// let (s, r): (Sender<GroupMessage>, Receiver<GroupMessage>) = unbounded();
    ///
    /// thread::spawn(move || {
    ///     loop {
    ///         match r.recv() {
    ///             Ok(m) => println!("{}", str::from_utf8(&m).unwrap()),
    ///             Err(e) => panic!("error reading: {:?}", e),
    ///         }
    ///     }
    /// });
    ///
    /// conn.recvfrom_loop(s)
    pub fn recvfrom_loop(&self, tx: Sender<GroupMessage>) {
        let buf: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE];
        let mut socket_addr = tipc_addr{type_: 0, instance: 0, node: 0, scope: 0};
        let mut member_addr = tipc_addr{type_: 0, instance: 0, node: 0, scope: 0};
        let mut err = 0;

        loop {
            let msg_size = unsafe {
                tipc_recvfrom(
                    self.socket,
                    buf.as_ptr() as *mut c_void,
                    buf.len() as u64,
                    &mut socket_addr,
                    &mut member_addr,
                    &mut err,
                )
            };

            let msg = if msg_size == 0 {
                GroupMessage::MemberEvent(
                    Membership{
                        socket_ref: socket_addr.instance,
                        node_ref: socket_addr.node,
                        service_address: member_addr.type_,
                        service_instance: member_addr.instance,
                        joined: if err == 0 { true } else { false },
                    }
                )
            } else {
                let data = buf[0..msg_size as usize].to_vec();
                GroupMessage::DataEvent(data)
            };
            if let Err(e) = tx.send(msg) {
                println!("Send error: {:?}", e);
            }
        }
    }

    fn send_to(&self, data: &[u8], addr: &tipc_addr) -> c_int {
        unsafe {
            tipc_sendto(
                self.socket,
                data.as_ptr() as *const c_void,
                data.len() as size_t,
                addr,
            )
        }
    }
}

fn socket_and_node_refs(socket: c_int) -> TipcResult<(u32, u32)> {
    let mut addr = tipc_addr {
        type_: 0,
        instance: 0,
        node: 0,
        scope: 0,
    };
    let r = unsafe { tipc_sockaddr(socket, &mut addr) };
    if r < 0 {
        return Err(TipcError::new("Unable to determine socket and node refs"))
    }

    Ok((addr.instance, addr.node))
}

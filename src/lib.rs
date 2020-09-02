//! Linux [Transparent Inter Process Communication (TIPC)][1] bindings for Rust
//!
//! [1]: http://tipc.io/
//!
//! This library provides bindings for some of the more common TIPC operations.
//!
//! ## Prerequisites
//! * Linux OS
//! * clang
//! * TIPC kernel module enabled (`sudo modprobe tipc`)
//!
//! ### Open a socket, bind to an address and listen for messages
//! ```ignore
//! use tipc::{TipcConn, SockType, TipcScope};
//! let conn = TipcConn::new(SockType::SockRdm).unwrap();
//!
//! conn.bind(12345, 0, 0, TipcScope::Cluster).expect("Unable to bind to address");
//! let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
//! loop {
//!     let msg_size = conn.recv(&mut buf).unwrap();
//!     println!("received: {}", std::str::from_utf8(&buf[0..msg_size as usize]).unwrap())
//! }
//! ```
//!
//! ### Join a group and listen for group membership events or messages
//! Note: Joining a group automatically binds to an address and creates the group
//! if it doesn't already exist.
//! ```ignore
//! use tipc::{TipcConn, SockType, TipcScope, GroupMessage};
//! let conn = TipcConn::new(SockType::SockRdm).unwrap();
//!
//! conn.join(12345, 1, TipcScope::Cluster).expect("Unable to join group");
//!
//! // Listen for messages
//! loop {
//!     match conn.recvfrom().unwrap() {
//!         GroupMessage::MemberEvent(e) => {
//!             let action = if e.joined() { "joined" } else { "left" };
//!             println!("group member {}:{} {}", e.socket_ref(), e.node_ref(), action);
//!         },
//!         GroupMessage::DataEvent(d) => {
//!             println!("received message: {}", std::str::from_utf8(&d).unwrap());
//!         }
//!     }
//! }
//! ```

use std::os::raw::{c_int, c_void};

mod bindings;
mod cmd;
mod error;
mod group;

use bindings::*;
pub use cmd::{attach_to_interface, set_host_addr};
pub use error::TipcError;
pub use group::{GroupMessage, Membership};

pub const MAX_MSG_SIZE: usize = TIPC_MAX_USER_MSG_SIZE as usize;

#[derive(Debug, Clone, Copy)]
/// The scope to use when binding to an address.
/// ```
/// # use tipc::TipcScope;
/// assert_eq!(TipcScope::Cluster as u32, 2);
/// assert_eq!(TipcScope::Node as u32, 3);
/// ```
pub enum TipcScope {
    Cluster = TIPC_CLUSTER_SCOPE as isize,
    Node = TIPC_NODE_SCOPE as isize,
}

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
    buf: Vec<u8>,
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
            return Err(TipcError::new("Unable to initialize socket"));
        }

        let (socket_ref, node_ref) = socket_and_node_refs(socket)?;
        Ok(Self {
            socket,
            socket_ref,
            node_ref,
            buf: [0; MAX_MSG_SIZE].to_vec()
        })
    }

    /// Set the socket to be non-blocking. This causes socket calls to return a
    /// TipcError with EAGAIN | EWOULDBLOCK error code set when it's not possible
    /// to send/recv on the socket.
    pub fn set_sock_non_block(&mut self) -> TipcResult<()> {
        self.socket = unsafe { tipc_sock_non_block(self.socket) };
        Ok(())
    }

    /// Connect a stream socket.
    pub fn connect(
        &self,
        service_type: u32,
        service_instance: u32,
        node: u32,
        scope: TipcScope,
    ) -> TipcResult<()> {
        let addr = tipc_addr {
            type_: service_type,
            instance: service_instance,
            node,
            scope: scope as u32,
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
        Ok(Self {
            socket,
            socket_ref,
            node_ref,
            buf: [0; MAX_MSG_SIZE].to_vec()
        })
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

        Ok(r)
    }

    /// Broadcast data to every node in a group. Returns the number
    /// of bytes sent.
    pub fn broadcast(&self, data: &[u8]) -> TipcResult<i32> {
        self.send(data)
    }

    /// Anycast data to a random node bound to `service_type` and `service_instance`. TIPC
    /// protocol will round-robin available hosts. If this call is made in a group, TIPC will
    /// also take into consideration the destination's load, possible passing it by to
    /// pick another node.
    pub fn anycast(
        &self,
        data: &[u8],
        service_type: u32,
        service_instance: u32,
        scope: TipcScope
    ) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: service_type,
            instance: service_instance,
            node: 0,
            scope: scope as u32,
        };
        let bytes_sent = self.send_to(data, &addr);
        if bytes_sent < 0 {
            return Err(TipcError::new("Anycast error"));
        }
        Ok(bytes_sent)
    }

    /// Unicast data to a specific socket address. Returns the number of bytes sent.
    pub fn unicast(
        &self,
        data: &[u8],
        socket_ref: u32,
        node_ref: u32,
        scope: TipcScope,
    ) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: 0,
            instance: socket_ref,
            node: node_ref,
            scope: scope as u32,
        };

        let bytes_sent = self.send_to(data, &addr);
        if bytes_sent < 0 {
            return Err(TipcError::new("Unicast error"));
        }
        Ok(bytes_sent)
    }

    /// Multicast data to every node bound to the address and range requested. Returns the
    /// number of bytes sent.
    pub fn multicast(
        &self,
        data: &[u8],
        service_type: u32,
        lower: u32,
        upper: u32,
        scope: TipcScope,
    ) -> TipcResult<i32> {
        let addr = tipc_addr {
            type_: service_type,
            instance: lower,
            node: upper,
            scope: scope as u32,
        };
        let bytes_sent = unsafe {
            tipc_mcast(
                self.socket,
                data.as_ptr() as *const c_void,
                data.len() as size_t,
                &addr,
            )
        };

        if bytes_sent < 0 {
            return Err(TipcError::new("Multicast error"));
        }
        Ok(bytes_sent)
    }

    /// Join a group. If the group doesn't exist, it is automatically created.
    pub fn join(&self, group_id: u32, member_id: u32, scope: TipcScope) -> TipcResult<()> {
        let mut addr = tipc_addr {
            type_: group_id,
            instance: member_id,
            node: 0,
            scope: scope as u32,
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

        Ok(())
    }

    /// Bind to an address and range.
    pub fn bind(
        &self,
        service_type: u32,
        service_instance: u32,
        node: u32,
        scope: TipcScope,
    ) -> TipcResult<()> {
        let r = unsafe {
            tipc_bind(
                self.socket,
                service_type,
                service_instance,
                node,
                scope as u32,
            )
        };
        if r < 0 {
            return Err(TipcError::new("Error binding to socket address"));
        }

        Ok(())
    }

    /// Receive data from a socket, copying it to the passed in buffer. Returns
    /// the number of bytes received.
    /// # Example
    /// ```ignore
    /// let conn = TipcConn::new(SockType::SockRdm).unwrap();
    /// conn.bind(88888, 0, 10, TipsScope::CLuster).expect("Unable to bind to address");
    /// let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
    /// loop {
    ///     let msg_size = conn.recv(&mut buf).unwrap();
    ///     println!("{}", std::str::from_utf8(&buf[0..msg_size as usize]).unwrap())
    /// }
    pub fn recv(&self, buf: &mut [u8; MAX_MSG_SIZE]) -> TipcResult<i32> {
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

        Ok(msg_size)
    }

    /// Receive data or group membership messages from the socket.
    /// # Example
    /// ```ignore
    /// let conn = TipcConn::new(SockType::SockRdm).unwrap();
    /// conn.join(88888, 10, TipsScope::CLuster).expect("Unable to join group");
    ///
    /// loop {
    ///     match conn.recvfrom() {
    ///         Ok(msg) => match msg {
    ///             GroupMessage::DataEvent(d) => {
    ///                 println!("group message: {}", std::str::from_utf8(&d).unwrap())
    ///             },
    ///             GroupMessage::MemberEvent(e) => {
    ///                 let event_type = if e.joined() { "joined" } else { "left" };
    ///                 println!("member {} {}", e, event_type);
    ///             },
    ///         Err(e) => panic!("error receiving from socket: {}", e),
    ///     }
    /// }
    pub fn recvfrom(&self) -> TipcResult<GroupMessage> {
        let mut socket_addr = tipc_addr {
            type_: 0,
            instance: 0,
            node: 0,
            scope: 0,
        };
        let mut member_addr = tipc_addr {
            type_: 0,
            instance: 0,
            node: 0,
            scope: 0,
        };
        let mut err = 0;

        let msg_size = unsafe {
            tipc_recvfrom(
                self.socket,
                self.buf.as_ptr() as *mut c_void,
                self.buf.len() as u64,
                &mut socket_addr,
                &mut member_addr,
                &mut err,
            )
        };

        if msg_size < 0 {
            return Err(TipcError::new("recvfrom error"));
        }

        let msg = if msg_size == 0 {
            GroupMessage::MemberEvent(Membership {
                socket_ref: socket_addr.instance,
                node_ref: socket_addr.node,
                service_address: member_addr.type_,
                service_instance: member_addr.instance,
                joined: if err == 0 { true } else { false },
            })
        } else {
            let data = self.buf[0..msg_size as usize].to_vec();
            GroupMessage::DataEvent(data)
        };

        Ok(msg)
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
        return Err(TipcError::new("Unable to determine socket and node refs"));
    }

    Ok((addr.instance, addr.node))
}

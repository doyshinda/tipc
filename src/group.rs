use std::fmt;

/// Information about a node that joined/left a group.
#[derive(Debug)]
pub struct Membership {
    pub(crate) socket_ref: u32,
    pub(crate) node_ref: u32,
    pub(crate) service_address: u32,
    pub(crate) service_instance: u32,
    pub(crate) joined: bool,
}

impl Membership {
    /// The unique socket ref for the process that opened the socket. This value is used
    /// when sending a message to a specific socket (unicasting).
    pub fn socket_ref(&self) -> u32 {
        self.socket_ref
    }
    /// The reference ID of the node where the process is running. This value is used
    /// when sending a message to a specific socket (unicasting).
    pub fn node_ref(&self) -> u32 {
        self.node_ref
    }

    /// The (possibly not unique) address to which the socket was bound. This value is
    /// used when [any/broad/multi]casting.
    pub fn service_type(&self) -> u32 {
        self.service_address
    }
    /// The (possibe not unique) instance to which the socket was bound. This value is
    /// used when [any/broad/multi]casting.
    pub fn service_instance(&self) -> u32 {
        self.service_instance
    }

    /// 'true' indicates a join, `false` indicates a leave
    pub fn joined(&self) -> bool {
        self.joined
    }
}

impl fmt::Display for Membership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}@{}:{}",
            self.service_address, self.service_instance, self.socket_ref, self.node_ref
        )
    }
}

#[derive(Debug)]
/// Represents the message type received when in a group.
pub enum GroupMessage {
    /// Information about a node joining/leaving the group (automatically genereated by TIPC).
    MemberEvent(Membership),

    /// A user-initiated message.
    DataEvent(Vec<u8>),
}

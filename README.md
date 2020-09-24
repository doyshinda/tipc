# tipc
Rust Bindings for some of the common Linux TIPC operations.

## Prerequisites
* Linux OS (version >= 4.14 for communication groups)
* Clang compiler
* TIPC kernel module enabled (`sudo modprobe tipc`)

## Building tipc
```sh
$ git clone https://github.com/doyshinda/tipc.git
$ cd tipc
$ cargo build [--release]
```

## Testing
By default, Rust will run tests in parallel, which causes havoc when many different tests are trying to create/join the same TIPC group. Use the following make target, which pins the number of test threads to 1:
```sh
$ make test
```

Alternatively, you can invoke the following cargo command directly:
```sh
cargo test -- --test-threads=1
```

## Examples
### Attach TIPC to an interface for communication with other nodes on the network
```rust
use tipc::attach_to_interface;
attach_to_interface("eth0").unwrap();
```

### Open a socket, bind to an address and listen for messages
```rust
use tipc::{TipcConn, SockType, TipcScope};
let conn = TipcConn::new(SockType::SockRdm).unwrap();

conn.bind(12345, 0, 0, TipcScope::Cluster).expect("Unable to bind to address");
let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
loop {
    let msg_size = conn.recv(&mut buf).unwrap();
    println!("received: {}", std::str::from_utf8(&buf[0..msg_size as usize]).unwrap())
}
```

In another machine on the network:
```rust
use std::{thread, time};
use tipc::{TipcConn, SockType, TipcScope};
let conn = TipcConn::new(SockType::SockRdm).unwrap();

let n = 0;
loop {
    let data = format!("Client multicast testing {}", n);
    conn.multicast(data.as_bytes(), 12345, 0, 0, TipcScope::Cluster).unwrap();
    n += 1;
    thread::sleep(time::Duration::from_secs(1));
}
```

### Join a group and listen for group membership events or messages
Note: Joining a group automatically binds to an address and creates the group
if it doesn't already exist.
```rust
use tipc::{TipcConn, SockType, TipcScope, GroupMessage};
let mut conn = TipcConn::new(SockType::SockRdm).unwrap();

conn.join(12345, 1, TipcScope::Cluster).expect("Unable to join group");

// Listen for messages
loop {
    match conn.recvfrom().unwrap() {
        GroupMessage::MemberEvent(e) => {
            let action = if e.joined() { "joined" } else { "left" };
            println!("group member {}:{} {}", e.socket_ref(), e.node_ref(), action);
        },
        GroupMessage::DataEvent(d) => {
            println!("received message: {}", std::str::from_utf8(&d).unwrap());
        }
    }
}
```

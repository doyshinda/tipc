use tipc::{TipcConn, SockType};

fn main() {
    // tipc::attach_to_interface("wlp3s0")
    let conn = match TipcConn::new(SockType::SockRDM) {
        Err(e) => panic!("{}", e.description),
        Ok(c) => c
    };
    conn.broadcast("Testing from Rust", 88888u32);
}

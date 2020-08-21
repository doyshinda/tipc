use tipc::{TipcConn, SockType};

fn main() {
    let conn = match TipcConn::new(SockType::SockRDM) {
        Err(e) => panic!("{}", e.description),
        Ok(c) => c
    };

    if let Ok(bytes_sent) = conn.broadcast("Testing from Rust", 88888u32) {
        println!("successfully sent {} bytes", bytes_sent);
    }
}

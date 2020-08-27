use tipc::{SockType, TipcConn, TipcAddr, GroupMessage};
use crossbeam_channel::{unbounded, Sender, Receiver};
use std::thread;
use std::time::Duration;

const SERVER_ADDR_1: TipcAddr = TipcAddr{
    service_type: 12345,
    instance: 0,
    node: 0,
    scope: tipc::TipcScope::Cluster
};
const CLIENT_ADDR_1: TipcAddr = TipcAddr{
    service_type: 12345,
    instance: 100,
    node: 0,
    scope: tipc::TipcScope::Cluster
};
static TEST_MESSAGE: &str = "Test Message";

#[test]
fn test_set_non_blocking_returns_error() {
    let mut conn = TipcConn::new(SockType::SockStream).unwrap();
    conn.set_sock_non_block().unwrap();

    conn.bind(&SERVER_ADDR_1).unwrap();
    conn.listen(1).unwrap();
    let e = conn.accept().unwrap_err();
    assert_eq!(e.code(), 11);
}

#[test]
fn test_anycast() {
    let server = setup_listen_server(SockType::SockRdm);
    let client = TipcConn::new(SockType::SockRdm).unwrap();

    let bytes_sent = client.anycast(TEST_MESSAGE.as_bytes(), &SERVER_ADDR_1).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    assert_message_received(&server, TEST_MESSAGE);
}

#[test]
fn test_broadcast() {
    let server = TipcConn::new(SockType::SockRdm).unwrap();
    server.join(&SERVER_ADDR_1).unwrap();

    let client = TipcConn::new(SockType::SockRdm).unwrap();
    client.join(&CLIENT_ADDR_1).unwrap();

    let bytes_sent = client.broadcast(TEST_MESSAGE.as_bytes()).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    // First message is member join message, no length
    assert_message_received(&server, "");
    assert_message_received(&server, TEST_MESSAGE);
}

#[test]
fn test_multicast() {
    let server = setup_listen_server(SockType::SockRdm);
    let client = TipcConn::new(SockType::SockRdm).unwrap();

    let bytes_sent = client.multicast(TEST_MESSAGE.as_bytes(), &SERVER_ADDR_1).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    assert_message_received(&server, TEST_MESSAGE);
}

#[test]
fn test_unicast() {
    let server = setup_listen_server(SockType::SockRdm);
    let server_addr = TipcAddr {
        service_type: 0,
        instance: server.socket_ref(),
        node: server.node_ref(),
        scope: tipc::TipcScope::Cluster,
    };

    let client = TipcConn::new(SockType::SockRdm).unwrap();
    let bytes_sent = client.unicast(TEST_MESSAGE.as_bytes(), &server_addr).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    assert_message_received(&server, TEST_MESSAGE);
}

#[test]
fn test_connect_and_send() {
    let server = setup_listen_server(SockType::SockSeqpacket);
    server.listen(1).unwrap();
    let t1 = thread::spawn(move || {
        let new_conn = server.accept().unwrap();
        assert_message_received(&new_conn, TEST_MESSAGE);
    });

    let client = TipcConn::new(SockType::SockSeqpacket).unwrap();
    client.connect(&SERVER_ADDR_1).unwrap();

    let bytes_sent = client.send(TEST_MESSAGE.as_bytes()).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    t1.join().expect("Couldn't join on the associated thread")
}

#[test]
fn test_join_and_leave_membership_event() {
    let server = TipcConn::new(SockType::SockRdm).unwrap();
    server.join(&SERVER_ADDR_1).unwrap();
    let (s, r): (Sender<GroupMessage>, Receiver<GroupMessage>) = unbounded();
    let t1 = thread::spawn(move || {
        // First message will be a join
        match r.recv().unwrap() {
            GroupMessage::MemberEvent(e) => {
                assert!(e.joined());
                assert_eq!(e.service_type(), CLIENT_ADDR_1.service_type);
                assert_eq!(e.service_instance(), CLIENT_ADDR_1.instance);
            }
            _ => panic!("Unexpected data group data message"),
        }

        // Second message will be a leave
        match r.recv().unwrap() {
            GroupMessage::MemberEvent(e) => {
                assert!(!e.joined());
                assert_eq!(e.service_type(), CLIENT_ADDR_1.service_type);
                assert_eq!(e.service_instance(), CLIENT_ADDR_1.instance);
            }
            _ => panic!("Unexpected data group data message"),
        }
    });

    thread::spawn(move || server.recvfrom_loop(s));

    let client = TipcConn::new(SockType::SockRdm).unwrap();
    client.join(&CLIENT_ADDR_1).unwrap();
    thread::sleep(Duration::from_millis(100));
    client.leave().unwrap();

    t1.join().expect("Couldn't join on the associated thread")
}

fn setup_listen_server(socktype: SockType) -> TipcConn {
    let server = TipcConn::new(socktype).unwrap();
    server.bind(&SERVER_ADDR_1).unwrap();
    server
}

fn assert_message_received(conn: &TipcConn, expected_msg: &str) {
    let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
    let msg_size = conn.recv_buf(&mut buf).unwrap();

    assert_eq!(
        std::str::from_utf8(&buf[0..msg_size as usize]).unwrap(),
        expected_msg
    );
}

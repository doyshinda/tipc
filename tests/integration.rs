use std::thread;
use std::time::Duration;
use tipc::{GroupMessage, SockType, TipcConn};

const SERVER_ADDR: u32 = 12345u32;
const SERVER_INST: u32 = 0u32;
const SERVER_NODE: u32 = 0u32;
const SERVER_SCOPE: tipc::TipcScope = tipc::TipcScope::Cluster;

const CLIENT_ADDR: u32 = 12345;
const CLIENT_INST: u32 = 100;
const CLIENT_SCOPE: tipc::TipcScope = tipc::TipcScope::Cluster;

static TEST_MESSAGE: &str = "Test Message";

#[test]
fn test_set_non_blocking_returns_error() {
    let mut conn = TipcConn::new(SockType::SockStream).unwrap();
    conn.set_sock_non_block().unwrap();

    conn.bind(SERVER_ADDR, SERVER_INST, SERVER_NODE, SERVER_SCOPE)
        .unwrap();
    conn.listen(1).unwrap();
    let e = conn.accept().unwrap_err();
    assert_eq!(e.code(), 11);
}

#[test]
fn test_anycast() {
    let mut server1 = setup_listen_server(SockType::SockRdm);
    let mut server2 = setup_listen_server(SockType::SockRdm);

    server1.set_sock_non_block().unwrap();
    server2.set_sock_non_block().unwrap();

    let client = TipcConn::new(SockType::SockRdm).unwrap();

    let bytes_sent = client
        .anycast(
            TEST_MESSAGE.as_bytes(),
            SERVER_ADDR,
            SERVER_INST,
            SERVER_SCOPE,
        )
        .unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];

    let r = server1.recv(&mut buf);

    let mut next_server = &server1;
    if r.is_err() {
        // server2 received the first message
        assert_message_received(&server2, TEST_MESSAGE);
        assert_eq!(r.unwrap_err().code(), 11);
    } else {
        // server1 received the first message
        let msg_size = r.unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[0..msg_size as usize]).unwrap(),
            TEST_MESSAGE
        );
        next_server = &server2;
    }

    // Send another message and ensure next_server receives this one
    let bytes_sent = client
        .anycast(
            TEST_MESSAGE.as_bytes(),
            SERVER_ADDR,
            SERVER_INST,
            SERVER_SCOPE,
        )
        .unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());
    assert_message_received(next_server, TEST_MESSAGE);
}

#[test]
fn test_broadcast() {
    let mut server1 = TipcConn::new(SockType::SockRdm).unwrap();
    server1
        .join(SERVER_ADDR, SERVER_INST, SERVER_SCOPE)
        .unwrap();

    let mut server2 = TipcConn::new(SockType::SockRdm).unwrap();
    server2
        .join(SERVER_ADDR, SERVER_INST + 1, SERVER_SCOPE)
        .unwrap();

    // Both servers receive a message for each other's join
    assert_message_received(&server1, "");
    assert_message_received(&server2, "");

    let mut client = TipcConn::new(SockType::SockRdm).unwrap();
    client.join(CLIENT_ADDR, CLIENT_INST, CLIENT_SCOPE).unwrap();

    // Servers receive message for client joining
    assert_message_received(&server1, "");
    assert_message_received(&server2, "");

    let bytes_sent = client.broadcast(TEST_MESSAGE.as_bytes()).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    assert_message_received(&server1, TEST_MESSAGE);
    assert_message_received(&server2, TEST_MESSAGE);
}

#[test]
fn test_multicast() {
    let mut server1 = setup_listen_server(SockType::SockRdm);
    let mut server2 = setup_listen_server(SockType::SockRdm);

    server1.set_sock_non_block().unwrap();
    server2.set_sock_non_block().unwrap();

    let client = TipcConn::new(SockType::SockRdm).unwrap();
    let bytes_sent = client
        .multicast(
            TEST_MESSAGE.as_bytes(),
            SERVER_ADDR,
            SERVER_INST,
            SERVER_INST + 1,
            SERVER_SCOPE,
        )
        .unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    assert_message_received(&server1, TEST_MESSAGE);
    assert_message_received(&server2, TEST_MESSAGE);
}

#[test]
fn test_unicast() {
    let server = setup_listen_server(SockType::SockRdm);

    let client = TipcConn::new(SockType::SockRdm).unwrap();
    let bytes_sent = client
        .unicast(
            TEST_MESSAGE.as_bytes(),
            server.socket_ref(),
            server.node_ref(),
            SERVER_SCOPE,
        )
        .unwrap();

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
    client
        .connect(SERVER_ADDR, SERVER_INST, SERVER_NODE, SERVER_SCOPE)
        .unwrap();

    let bytes_sent = client.send(TEST_MESSAGE.as_bytes()).unwrap();
    assert_eq!(bytes_sent as usize, TEST_MESSAGE.len());

    t1.join().expect("Couldn't join on the associated thread")
}

#[test]
fn test_join_and_leave_membership_event() {
    let mut server = TipcConn::new(SockType::SockRdm).unwrap();
    server.join(SERVER_ADDR, SERVER_INST, SERVER_SCOPE).unwrap();

    let t1 = thread::spawn(move || {
        // First message will be a join
        match server.recvfrom().unwrap() {
            GroupMessage::MemberEvent(e) => {
                assert!(e.joined());
                assert_eq!(e.service_type(), CLIENT_ADDR);
                assert_eq!(e.service_instance(), CLIENT_INST);
            }
            _ => panic!("Unexpected data group data message"),
        }

        // Second message will be a leave
        match server.recvfrom().unwrap() {
            GroupMessage::MemberEvent(e) => {
                assert!(!e.joined());
                assert_eq!(e.service_type(), CLIENT_ADDR);
                assert_eq!(e.service_instance(), CLIENT_INST);
            }
            _ => panic!("Unexpected data group data message"),
        }
    });

    let mut client = TipcConn::new(SockType::SockRdm).unwrap();
    client.join(CLIENT_ADDR, CLIENT_INST, CLIENT_SCOPE).unwrap();
    thread::sleep(Duration::from_millis(100));
    client.leave().unwrap();

    t1.join().expect("Couldn't join on the associated thread")
}

fn setup_listen_server(socktype: SockType) -> TipcConn {
    let server = TipcConn::new(socktype).unwrap();
    server
        .bind(SERVER_ADDR, SERVER_INST, SERVER_NODE, SERVER_SCOPE)
        .unwrap();
    server
}

fn assert_message_received(conn: &TipcConn, expected_msg: &str) {
    let mut buf: [u8; tipc::MAX_MSG_SIZE] = [0; tipc::MAX_MSG_SIZE];
    let msg_size = conn.recv(&mut buf).unwrap();

    assert_eq!(
        std::str::from_utf8(&buf[0..msg_size as usize]).unwrap(),
        expected_msg
    );
}

use tipc::{TipcConn, SockType};
use std::{thread, time};
use crossbeam_channel::{unbounded, Sender, Receiver};
use clap::{App, Arg};

fn handle_messages(r: Receiver<Vec<u8>>) {
    loop {
        match r.recv() {
            Ok(m) => println!("{}", std::str::from_utf8(&m).unwrap()),
            Err(e) => panic!("error reading: {:?}", e),
        }
    }
}

fn main() {
    let matches = App::new("My Super Program")
        .version("1.0")
        .author("Abe Friesen")
        .about("Does awesome things")
        .arg(Arg::with_name("address")
            .short("a")
            .value_name("ADDRESSf")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("instance")
            .short("i")
            // .long("instance")
            // .value_name("INST")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("group")
            .short("g"))
        .arg(Arg::with_name("client")
            .short("c"))
        .arg(Arg::with_name("recipient")
            .short("r")
            .takes_value(true))
        .arg(Arg::with_name("broadcast")
            .short("b"))
        .get_matches();

    tipc::attach_to_interface("wlp3s0");
    let is_client = matches.is_present("client");
    let conn = TipcConn::new(SockType::SOCK_RDM).unwrap();

    let is_group = matches.is_present("group");
    let a = matches.value_of("address").unwrap();
    let a = a.parse::<u32>().unwrap();
    let i = matches.value_of("instance").unwrap();
    let i = i.parse::<u32>().unwrap();
    let r = matches.value_of("recipient").unwrap_or("88888");
    let r = r.parse::<u32>().unwrap();
    println!("a: {}, i: {}, r: {}, client: {} group: {}", a, i, r, is_client, is_group);

    if is_group {
        println!("joined group {:?}", a);
        conn.join(a, i).unwrap();
    }
    if is_client {
        let mut n = 0;
        loop {
            if matches.is_present("broadcast") {
                conn.broadcast(&format!("Client multicast testing {}", n), r).unwrap();
            } else {
                conn.anycast(&format!("Client anycast testing {}", n), r).unwrap();
            }
            n += 1;
            thread::sleep(time::Duration::from_secs(1));
        }
    } else {
        if !is_group {
            conn.bind(a, i, i, tipc::TIPC_CLUSTER_SCOPE).expect("Unable to bind to address");
        }
        let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();

        thread::spawn(move || handle_messages(r));
        conn.recv(s);
    }

    // if let Ok(bytes_sent) = conn.broadcast("Testing from Rust", 88888u32) {
    //     println!("successfully sent {} bytes", bytes_sent);
    // }

    // let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    // conn.bind(88888, 69, 69, 0).expect("Unable to bind to address");

    // thread::spawn(move || handle_messages(r));
    // thread::spawn(move || { conn.recv(s) });

    // conn.recv(s);
    // for _i in 0..=30 {
    //     // conn.broadcast("Testing from Rust", 88887).unwrap();
    //     conn.anycast("Testing from Rust", 88888).unwrap();
    //     thread::sleep(time::Duration::from_secs(1));
    // }

    // conn.anycast(88888, "Testing from Rust");

    // let conn = TipcConn::new(SockType::SOCK_SEQPACKET).unwrap();
    // conn.connect(88888, 69, 0).unwrap();
    // assert_eq!(conn.send(b"foo").unwrap(), 3);
    // conn.listen(1).unwrap();
    // let new_conn = conn.accept().unwrap();
    // let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    // thread::spawn(move || {
    //     loop {
    //         match r.recv() {
    //             Ok(m) => println!("{}", str::from_utf8(&m).unwrap()),
    //             Err(e) => panic!("error reading: {:?}", e),
    //         }
    //     }
    // });

    // new_conn.recv(s);

    // let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    // thread::spawn(move || {
    //     loop {
    //         match r.recv() {
    //             Ok(m) => println!("{}", str::from_utf8(&m).unwrap()),
    //             Err(e) => panic!("error reading: {:?}", e),
    //         }
    //     }
    // });

    // conn.recv(s)
}

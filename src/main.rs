use tipc::{TipcConn, SockType, McastAddr, AcastAddr, UnicastAddr, TipcScope, BindAddr, GroupMessage};
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

fn print_group_message(m: &GroupMessage) {
    match m {
        GroupMessage::DATA_EVENT(d) => println!("group message: {}", std::str::from_utf8(&d).unwrap()),
        GroupMessage::MEMBER_EVENT(e) => {
            let event_type = if e.joined { "joined" } else { "left" };
            println!("member {} {}", e, event_type);
        }
    }
}

fn handle_group_messages(r: Receiver<GroupMessage>) {
    loop {
        match r.recv() {
            Ok(m) => print_group_message(&m),
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
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("group")
            .short("g"))
        .arg(Arg::with_name("client")
            .short("c"))
        .arg(Arg::with_name("recipient")
            .short("r")
            .takes_value(true))
        .arg(Arg::with_name("node")
            .short("n")
            .takes_value(true))
        .arg(Arg::with_name("multicast")
            .short("m"))
        .arg(Arg::with_name("anycast")
            .short("y"))
        .arg(Arg::with_name("broadcast")
            .short("b"))
        .arg(Arg::with_name("unicast")
            .short("u"))
        .get_matches();

    let is_client = matches.is_present("client");
    let mut conn = TipcConn::new(SockType::SOCK_RDM).unwrap();

    let is_group = matches.is_present("group");
    let a = matches.value_of("address").unwrap();
    let a = a.parse::<u32>().unwrap();
    let i = matches.value_of("instance").unwrap();
    let i = i.parse::<u32>().unwrap();
    let r = matches.value_of("recipient").unwrap_or("88888");
    let r = r.parse::<u32>().unwrap();
    let node = matches.value_of("node").unwrap_or("0");
    let node = node.parse::<u32>().unwrap();
    println!("a: {}, i: {}, r: {}, client: {} group: {}", a, i, r, is_client, is_group);

    if is_group {
        println!("joined group {:?}", a);
        conn.join(a, i, TipcScope::CLUSTER).unwrap();
    }
    if is_client {
        conn.set_sock_non_block().unwrap();
        let mut n = 0;
        loop {
            if matches.is_present("multicast") {
                let addr = McastAddr{server: r, lower: i, upper: i, scope: TipcScope::CLUSTER};
                let data = format!("Client multicast testing {}", n);
                let mut rc = -1;
                while rc < 0 {
                    match conn.multicast(data.as_bytes(), &addr) {
                        Ok(r) => rc = r,
                        Err(e) => {
                            if e.code == 11 {
                                println!("{}", "EAGAIN");
                                thread::sleep(time::Duration::from_millis(100));
                            } else {
                                rc = e.code;
                            }
                        }
                    }

                }
            }
            if matches.is_present("broadcast") {
                let data = format!("Client broadcast testing {}", n);
                println!("broadcast {}", n);
                conn.broadcast(data.as_bytes()).unwrap();
            }
            if matches.is_present("anycast") {
                let addr = AcastAddr{server: r, scope: TipcScope::CLUSTER};
                // let data = format!("Client anycast testing {}", n);
                let data = "Foo";
                let mut rc = -1;
                while rc < 0 {
                    match conn.anycast(data.as_bytes(), &addr) {
                        Ok(r) => rc = r,
                        Err(e) => {
                            if e.code == 11 {
                                println!("{}", "EAGAIN");
                                thread::sleep(time::Duration::from_millis(100));
                            } else {
                                rc = e.code;
                                println!("rc: {} err: {}", rc, e.description);
                            }
                        }
                    }

                }
            }
            if matches.is_present("unicast") {
                let addr = UnicastAddr{socket_id: r, node_id: node, scope: TipcScope::CLUSTER};
                let data = format!("Client unicast testing {}", n);
                conn.unicast(data.as_bytes(), &addr).unwrap();
            }
            n += 1;
            thread::sleep(time::Duration::from_secs(1));
        }
    } else {
        if !is_group {
            let addr = BindAddr{
                server: a,
                lower: i,
                upper: i,
                scope: TipcScope::CLUSTER,
            };
            conn.bind(&addr).expect("Unable to bind to address");
            let (s, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
            thread::spawn(move || handle_messages(r));
            conn.recv(s);
        } else {
            let (s, r): (Sender<GroupMessage>, Receiver<GroupMessage>) = unbounded();
            thread::spawn(move || handle_group_messages(r));
            conn.recvfrom(s);
        }


    }
}

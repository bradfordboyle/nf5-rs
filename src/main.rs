extern crate pcap;
extern crate pnet;
extern crate pnet_macros_support;

#[macro_use]
extern crate serde_json;
extern crate time;

mod packet;
use packet::netflow::NetflowPacket;

use std::env;
// use std::ops::Sub;
use std::path::Path;
use std::process;

use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ethernet::{EthernetPacket, EtherType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;

// use time::{Duration,Timespec};

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        let path = Path::new(&arg1);
        let mut cap = Capture::from_file(path).unwrap();

        while let Ok(packet) = cap.next() {
            let e = EthernetPacket::new(packet.data).unwrap();
            match e.get_ethertype() {
                EtherType(0x0800) => handle_ipv4(e.payload()),
                EtherType(_) => panic!("huh?"),
            }
        }
    } else {
        println!("pcap filename required");
        process::exit(1);
    }
}

fn handle_ipv4(d: &[u8]) {
    let i = Ipv4Packet::new(d).unwrap();

    match i.get_next_level_protocol() {
        IpNextHeaderProtocol(0x11) => handle_udp(i.payload()),
        IpNextHeaderProtocol(_) => panic!("huh?"),
    }
}

fn handle_udp(d: &[u8]) {
    let u = UdpPacket::new(d).unwrap();

    let dst_port = u.get_destination();
    match dst_port {
        9500 => handle_netflow(u.payload()),
        _ => panic!("huh?"),

    }
}

fn handle_netflow(d: &[u8]) {
    let n = NetflowPacket::new(d).unwrap();
    // let uptime = Duration::milliseconds(n.get_sys_uptime() as i64);
    // let current_time = time::at_utc(Timespec::new(n.get_unix_secs() as i64, n.get_unix_nsecs() as i32));
    // let boot = current_time.sub(uptime);

    for r in n.get_records() {
        let record = serde_json::to_string(&r).unwrap();
        println!("{}", record);
    }
}

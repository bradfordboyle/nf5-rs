extern crate pcap;
extern crate pnet;
extern crate pnet_macros_support;

mod packet;
use packet::netflow::NetflowPacket;

use std::env;
use std::path::Path;
use std::process;

use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        println!("The first argument is {}", arg1);
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
    // println!("{:?}", i);

    match i.get_next_level_protocol() {
        IpNextHeaderProtocol(0x11) => handle_udp(i.payload()),
        IpNextHeaderProtocol(_) => panic!("huh?"),
    }
}

fn handle_udp(d: &[u8]) {
    let u = UdpPacket::new(d).unwrap();
    // println!("{:?}", u);

    let dst_port = u.get_destination();
    // println!("dst_port = {}", dst_port);
    match dst_port {
        9500 => handle_netflow(u.payload()),
        _ => panic!("huh?"),

    }
}

fn handle_netflow(d: &[u8]) {
    let n = NetflowPacket::new(d).unwrap();
    for r in n.get_records() {
        println!("{:?}", r);
    }
}

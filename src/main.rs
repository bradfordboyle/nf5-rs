extern crate pcap;
extern crate pnet;
extern crate serde_json;

mod packet;

use packet::netflow::NetflowPacket;
use pcap::Capture;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::EtherTypes::Ipv4;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols::Udp;
use std::env;
use std::path::Path;
use std::process;

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        let path = Path::new(&arg1);
        let mut cap = Capture::from_file(path).unwrap();

        while let Ok(packet) = cap.next() {
            let e = EthernetPacket::new(packet.data).unwrap();
            match e.get_ethertype() {
                Ipv4 => handle_ipv4(e.payload()),
                _ => panic!("huh?"),
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
        Udp => handle_udp(i.payload()),
        _ => panic!("huh?"),
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
    let netflow = serde_json::to_string(&n.from_packet()).unwrap();
    println!("{}", netflow);
}

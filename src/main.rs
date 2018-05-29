extern crate pcap;
extern crate pnet;
extern crate pnet_macros_support;
extern crate serde;
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

use std::error;
use std::env;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        let path = Path::new(&arg1);
        let mut cap = Capture::from_file(path).unwrap();

        let n = NetflowVisitor;
        let u = UdpVisitor::new(n, 9500);
        let i = Ipv4Visitor::new(u);

        while let Ok(packet) = cap.next() {
            let e = EthernetPacket::new(packet.data).unwrap();
            match e.get_ethertype() {
                Ipv4 => i.accept(e.payload()).expect("unable to process packet"),
                _ => panic!("non-IPv4 packet found"),
            }
        }
    } else {
        println!("pcap filename required");
        process::exit(1);
    }
}

trait PacketVisitor {
    fn accept(&self, d: &[u8]) -> Result<(), Box<error::Error>>;
}

struct Ipv4Visitor<V> {
    next: V
}

impl<V> Ipv4Visitor<V> {
    pub fn new(next: V) -> Self {
        Self { next }
    }
}

impl<V: PacketVisitor> PacketVisitor for Ipv4Visitor<V> {
    fn accept(&self, d: &[u8]) -> Result<(), Box<error::Error>> {
        if let Some(i) = Ipv4Packet::new(d) {
            match i.get_next_level_protocol() {
                Udp => self.next.accept(i.payload()),
                _ => Err(From::from("non-UDP packet found"))
            }
        } else {
            Err(From::from("invalid IPv4 packet"))
        }
    }
}

struct UdpVisitor<V> {
    next: V,
    port: u16,
}

impl<V> UdpVisitor<V> {
    pub fn new(next: V, port: u16) -> Self {
        Self { next, port}
    }
}

impl<V: PacketVisitor> PacketVisitor for UdpVisitor<V> {
    fn accept(&self, d: &[u8]) -> Result<(), Box<error::Error>> {
        if let Some(u) = UdpPacket::new(d) {
            let dst_port = u.get_destination();
            if dst_port == self.port {
                self.next.accept(u.payload())
            } else {
                Err(From::from("encountered UDP packet with unexpected port"))
            }
        } else {
            Err(From::from("invalid UDP packet"))
        }
    }
}

struct NetflowVisitor;

impl PacketVisitor for NetflowVisitor {
    fn accept(&self, d: &[u8]) -> Result<(), Box<error::Error>> {
        if let Some(n) = NetflowPacket::new(d) {
            let netflow = serde_json::to_string(&n.from_packet())?;
            Ok(println!("{}", netflow))
        } else {
            Err(From::from("invalid Netflow v5 packet"))
        }
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

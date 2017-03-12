extern crate pcap;
extern crate pnet;
extern crate byteorder;

use std::path::Path;

use byteorder::{BigEndian, ReadBytesExt};
use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;


#[derive(Debug)]
struct Header {
    version: u16,
    count: u16,
    sys_uptime: u32,
    unix_secs: u32,
    unix_nsecs: u32,
    flow_seq: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_interval: u16
}


fn main() {
    println!("Hello, world!");

    let path = Path::new("./netflow000.10.pcap");
    let mut cap = Capture::from_file(path)
    .unwrap();

    while let Ok(packet) = cap.next() {
        let e = EthernetPacket::new(packet.data).unwrap();
        match e.get_ethertype() {
            EtherType(0x0800) => {
                handle_ipv4(e.payload());
            }
            EtherType(_) => {panic!("huh?");}
        }
    }

}

fn handle_ipv4(d: &[u8]) {
    let i = Ipv4Packet::new(d).unwrap();
    // println!("{:?}", i);

    match i.get_next_level_protocol() {
        IpNextHeaderProtocol(0x11) => {
            handle_udp(i.payload())
        }
        IpNextHeaderProtocol(_) => {
            panic!("huh?");
        }
    }
}

fn handle_udp(d: &[u8]) {
    let u = UdpPacket::new(d).unwrap();
    // println!("{:?}", u);

    let dst_port = u.get_destination();
    // println!("dst_port = {}", dst_port);
    match dst_port {
        9500 => {
            handle_netflow(u.payload())
        }
        _ => panic!("huh?")

    }
}

fn handle_netflow(d: &[u8]) {
    let mut rdr = std::io::Cursor::new(d);

    let hdr = Header {
        version: rdr.read_u16::<BigEndian>().unwrap(),
        count: rdr.read_u16::<BigEndian>().unwrap(),
        sys_uptime: rdr.read_u32::<BigEndian>().unwrap(),
        unix_secs: rdr.read_u32::<BigEndian>().unwrap(),
        unix_nsecs: rdr.read_u32::<BigEndian>().unwrap(),
        flow_seq: rdr.read_u32::<BigEndian>().unwrap(),
        engine_type: rdr.read_u8().unwrap(),
        engine_id: rdr.read_u8().unwrap(),
        sampling_interval: rdr.read_u16::<BigEndian>().unwrap(),
    };

    println!("header = {:?}", hdr);
}

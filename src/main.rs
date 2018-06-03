extern crate csv;
extern crate pcap;
extern crate pnet;
extern crate pnet_macros_support;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

mod packet;

use packet::netflow::Netflow;
use packet::netflow::NetflowPacket;
use packet::netflow::Record;
use pcap::Capture;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes::Ipv4;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols::Udp;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;

use std::env;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        let path = Path::new(&arg1);
        let mut cap = Capture::from_file(path).unwrap();

        let mut wtr = csv::Writer::from_writer(io::stdout());

        while let Ok(packet) = cap.next() {
            let ether = EthernetPacket::new(packet.data).expect("invalid ethernet packet");
            let ip = match ether.get_ethertype() {
                Ipv4 => Ipv4Packet::new(ether.payload()).expect("invalid IPv4 packet"),
                _ => panic!("non-IPv4 packet found"),
            };
            let udp = match ip.get_next_level_protocol() {
                Udp => UdpPacket::new(ip.payload()).expect("invalid UDP packet"),
                _ => panic!("non-UDP packet found"),
            };
            let nf5 = if udp.get_destination() == 9500 {
                NetflowPacket::new(udp.payload()).expect("invalid Netflow packet")
            } else {
                panic!("invalid UDP port found")
            };
            let netflow = nf5.from_packet();
            let boottime = netflow.boottime();

            for r in &netflow.records {
                let flow = Flow::from_pdu(&r, boottime);
                wtr.serialize(flow).expect("error writing to standard out");
            }
            wtr.flush().expect("error flushing standard out");
        }
    } else {
        println!("pcap filename required");
        process::exit(1);
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Flow {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    packets: u32,
    octets: u32,
    first: u64,
    last: u64,
    src_port: u16,
    dst_port: u16,
    prot: u8,
}

const MS_NANO_SECS: u64 = 1_000_000u64;

impl Flow {
    fn from_pdu(r: &Record, boottime: u64) -> Self {
        Self {
            source: r.source,
            destination: r.destination,
            packets: r.d_pkts,
            octets: r.d_octets,
            first: boottime + r.first as u64 * MS_NANO_SECS,
            last: boottime + r.last as u64 * MS_NANO_SECS,
            src_port: r.src_port,
            dst_port: r.dst_port,
            prot: r.prot,
        }
    }
}

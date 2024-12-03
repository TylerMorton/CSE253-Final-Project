#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
use core::u32;

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::bpf_redirect,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use core::mem;

#[repr(C)]
pub struct DhcpHdr {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8;64],
    pub file: [u8; 128],
    pub magic: u32,
}
impl DhcpHdr {
    pub const LEN: usize = mem::size_of::<DhcpHdr>();
}

// TODO:
pub struct DhcpOption {}


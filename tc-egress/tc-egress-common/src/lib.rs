#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
use core::mem;
use core::u32;

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
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub magic: u32,
}
impl DhcpHdr {
    pub const LEN: usize = mem::size_of::<DhcpHdr>();
}

// TODO:
pub struct DhcpOption {}

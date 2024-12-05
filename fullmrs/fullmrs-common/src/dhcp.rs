use core::mem;

// Has to be aligned to 8 bytes.
//pub const MAX_MTU: usize = 1504; // TODO: May need to be adjusted in future.
pub const MAX_MTU: usize = 200; // TODO: May need to be adjusted in future.

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

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketBuffer {
    pub size: usize,
    pub buf: [u8; MAX_MTU],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for PacketBuffer {}
}

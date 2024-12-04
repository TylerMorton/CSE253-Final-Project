// Has to be aligned to 8 bytes.
//pub const MAX_MTU: usize = 1504; // TODO: May need to be adjusted in future.
pub const MAX_MTU: usize = 200; // TODO: May need to be adjusted in future.

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
